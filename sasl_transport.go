package gohive

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/beltran/gosasl"
	"github.com/pkg/errors"
)

const (
	START    = 1
	OK       = 2
	BAD      = 3
	ERROR    = 4
	COMPLETE = 5
)

// TSaslTransport is a tranport thrift struct that uses SASL
type TSaslTransport struct {
	service        string
	saslClient     *gosasl.Client
	tp             thrift.TTransport
	tpFramed       thrift.TFramedTransport
	mechanism      string
	writeBuf       bytes.Buffer
	readBuf        bytes.Buffer
	buffer         [4]byte
	rawFrameSize   uint32 //Current remaining size of the frame. if ==0 read next frame header
	frameSize      int    //Current remaining size of the frame. if ==0 read next frame header
	maxLength      uint32
	principal      string
	OpeningContext context.Context

	// closeOnce/closeErr 保证 Close 幂等: Open 失败时会内部自调 Close 做清理,
	// 上层(如 gohive.innerConnect)拿到错误后往往还会再调一次 Close 兜底,
	// 没有幂等保护会导致 saslClient.Dispose 被重复调用, 在部分 native 实现下不安全。
	closeOnce sync.Once
	closeErr  error
}

// NewTSaslTransport return a TSaslTransport
func NewTSaslTransport(trans thrift.TTransport, host string, mechanismName string, configuration map[string]string, maxLength uint32) (*TSaslTransport, error) {
	var mechanism gosasl.Mechanism
	if mechanismName == "PLAIN" {
		mechanism = gosasl.NewPlainMechanism(configuration["username"], configuration["password"])
	} else if mechanismName == "GSSAPI" {
		var err error
		mechanism, err = gosasl.NewGSSAPIMechanism(configuration["service"])
		if err != nil {
			return nil, err
		}
	} else if mechanismName == "DIGEST-MD5" {
		mechanism = gosasl.NewDigestMD5Mechanism(configuration["service"], configuration["username"], configuration["password"])
	} else {
		panic("Mechanism not supported")
	}
	client := gosasl.NewSaslClient(host, mechanism)
	return &TSaslTransport{
		saslClient:     client,
		tp:             trans,
		mechanism:      mechanismName,
		maxLength:      maxLength,
		principal:      configuration["principal"],
		OpeningContext: context.Background(),
	}, nil
}

// IsOpen opens a SASL connection
func (p *TSaslTransport) IsOpen() bool {
	return p.tp.IsOpen() && p.saslClient.Complete()
}

// Open check if a SASL transport connection is opened
func (p *TSaslTransport) Open() (err error) {
	// 关键修复: Open 中途任何一步失败(tp.Open/SASL 握手各阶段)都不能直接 return,
	// 否则已打开的底层 socket、已创建的 saslClient(可能已持有 GSSAPI native
	// context/凭据)会半开泄漏, 上层拿到的只是 nil,err, 无法再补救释放。
	// 这里通过 defer 保证: 只要 Open 最终失败, 一定会调用 Close 做统一清理;
	// Close 本身是幂等的(见下), 不会因外层再调一次 Close 而重复释放。
	defer func() {
		if err == nil {
			return
		}
		if closeErr := p.Close(); closeErr != nil {
			err = errors.Wrapf(err, "close after open failure also failed: %v", closeErr)
		}
	}()

	if !p.tp.IsOpen() {
		err = p.tp.Open()
		if err != nil {
			return err
		}
	}
	if err = p.sendSaslMsg(p.OpeningContext, START, []byte(p.mechanism)); err != nil {
		return err
	}

	proccessed, err := p.saslClient.Start()
	if err != nil {
		return err
	}

	if err = p.sendSaslMsg(p.OpeningContext, OK, proccessed); err != nil {
		return err
	}

	for true {
		status, challenge := p.recvSaslMsg(p.OpeningContext)
		if status == OK {
			proccessed, err = p.saslClient.Step(challenge)
			if err != nil {
				return
			}
			// 原实现忽略了这里的错误返回值: 若发送在握手中途失败(如连接被对端重置),
			// 会被当作握手仍在正常进行, 导致后续 recvSaslMsg 在已损坏的连接上继续阻塞/读错数据。
			if err = p.sendSaslMsg(p.OpeningContext, OK, proccessed); err != nil {
				return err
			}
		} else if status == COMPLETE {
			if !p.saslClient.Complete() {
				return thrift.NewTTransportException(thrift.NOT_OPEN, "The server erroneously indicated that SASL negotiation was complete")
			}
			break
		} else {
			return thrift.NewTTransportExceptionFromError(errors.Errorf("Bad SASL negotiation status: %d (%s)", status, challenge))
		}
	}
	return nil
}

// Close close a SASL transport connection
//
// 幂等: 使用 sync.Once 保护, 避免 Open 失败自清理 + 上层兜底再调一次 Close
// 导致 saslClient.Dispose()/底层 GSSAPI 释放被执行两次。
func (p *TSaslTransport) Close() error {
	p.closeOnce.Do(func() {
		if p.saslClient != nil {
			p.saslClient.Dispose()
		}
		if p.tp != nil {
			p.closeErr = p.tp.Close()
		}
	})
	return p.closeErr
}

func (p *TSaslTransport) sendSaslMsg(ctx context.Context, status uint8, body []byte) error {
	header := make([]byte, 5)
	header[0] = status
	length := uint32(len(body))
	binary.BigEndian.PutUint32(header[1:], length)

	_, err := p.tp.Write(append(header[:], body[:]...))
	if err != nil {
		return err
	}

	err = p.tp.Flush(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (p *TSaslTransport) recvSaslMsg(ctx context.Context) (int8, []byte) {
	header := make([]byte, 5)
	_, err := io.ReadFull(p.tp, header)
	if err != nil {
		return ERROR, nil
	}

	status := int8(header[0])
	length := binary.BigEndian.Uint32(header[1:])

	if length > 0 {
		payload := make([]byte, length)
		_, err = io.ReadFull(p.tp, payload)
		if err != nil {
			return ERROR, nil
		}
		return status, payload
	}
	return status, nil
}

func (p *TSaslTransport) Read(buf []byte) (l int, err error) {
	if p.rawFrameSize == 0 && p.frameSize == 0 {
		p.rawFrameSize, err = p.readFrameHeader()
		if err != nil {
			return
		}
	}

	var got int
	if p.rawFrameSize > 0 {
		rawBuf := make([]byte, p.rawFrameSize)
		got, err = io.ReadFull(p.tp, rawBuf)
		if err != nil {
			return
		}
		p.rawFrameSize = p.rawFrameSize - uint32(got)

		var unwrappedBuf []byte
		unwrappedBuf, err = p.saslClient.Decode(rawBuf)
		if err != nil {
			return
		}
		p.frameSize += len(unwrappedBuf)
		p.readBuf.Write(unwrappedBuf)
	}

	// totalBytes := p.readBuf.Len()
	got, err = p.readBuf.Read(buf)
	p.frameSize = p.frameSize - got

	/*
		if p.readBuf.Len() > 0 {
			err = thrift.NewTTransportExceptionFromError(fmt.Errorf("Not enough frame size %d to read %d bytes", p.frameSize, totalBytes))
			return
		}
	*/
	if p.frameSize < 0 {
		return 0, thrift.NewTTransportException(thrift.UNKNOWN_TRANSPORT_EXCEPTION, "Negative frame size")
	}
	return got, thrift.NewTTransportExceptionFromError(err)
}

func (p *TSaslTransport) readFrameHeader() (uint32, error) {
	buf := p.buffer[:4]
	if _, err := io.ReadFull(p.tp, buf); err != nil {
		return 0, err
	}
	size := binary.BigEndian.Uint32(buf)
	if size < 0 {
		return 0, thrift.NewTTransportException(thrift.UNKNOWN_TRANSPORT_EXCEPTION, fmt.Sprintf("Incorrect frame size (%d)", size))
	}
	if size > p.maxLength {
		return 0, thrift.NewTTransportException(thrift.UNKNOWN_TRANSPORT_EXCEPTION, fmt.Sprintf("Frame size is bigger than allowed, set configuration.MaxLength (%d)", size))
	}
	return size, nil
}

func (p *TSaslTransport) Write(buf []byte) (int, error) {
	n, err := p.writeBuf.Write(buf)
	return n, thrift.NewTTransportExceptionFromError(err)
}

// Flush the bytes in the buffer
func (p *TSaslTransport) Flush(ctx context.Context) (err error) {
	wrappedBuf, err := p.saslClient.Encode(p.writeBuf.Bytes())
	if err != nil {
		return thrift.NewTTransportExceptionFromError(err)
	}

	p.writeBuf.Reset()

	size := len(wrappedBuf)
	buf := p.buffer[:4]
	binary.BigEndian.PutUint32(buf, uint32(size))
	_, err = p.tp.Write(buf)

	if err != nil {
		return thrift.NewTTransportExceptionFromError(err)
	}

	if size > 0 {
		if _, err := p.tp.Write(wrappedBuf); err != nil {
			return thrift.NewTTransportExceptionFromError(err)
		}
	}
	err = p.tp.Flush(ctx)
	return thrift.NewTTransportExceptionFromError(err)
}

// RemainingBytes return the size of the unwrapped bytes
func (p *TSaslTransport) RemainingBytes() uint64 {
	return uint64(p.frameSize)
}

// SetMaxLength set the maxLength
func (p *TSaslTransport) SetMaxLength(maxLength uint32) {
	p.maxLength = maxLength
}
