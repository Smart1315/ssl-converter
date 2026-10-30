//go:build js && wasm

// 브라우저(Web Worker)에서 실행되는 진입점. 전역 객체 sslConverter 에 analyze/convert 를 등록한다.
// 두 함수 모두 Promise 를 돌려주며, 결과 형식은 web/bridge.js 가 Java 판 API 응답(fetch Response)으로 바꾼다.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"syscall/js"
	"time"

	"sslconverter/cert"
)

func main() {
	// Go 의 WebAssembly 런타임은 시간대를 모르므로 브라우저의 시간대로 맞춘다
	offset := js.Global().Get("Date").New().Call("getTimezoneOffset").Int()
	time.Local = time.FixedZone("Local", -offset*60)

	api := js.Global().Get("Object").New()
	api.Set("analyze", js.FuncOf(func(_ js.Value, args []js.Value) any {
		request := args[0]
		return promise(func() (map[string]any, error) {
			analysis := cert.Analyze(sources(request), str(request, "password"), str(request, "alias"))
			encoded, err := json.Marshal(analysis)
			if err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "status": 200, "json": string(encoded)}, nil
		})
	}))
	api.Set("convert", js.FuncOf(func(_ js.Value, args []js.Value) any {
		request := args[0]
		return promise(func() (map[string]any, error) {
			options, err := exportOptions(request)
			if err != nil {
				return nil, err
			}
			file, err := cert.Convert(sources(request), str(request, "password"), str(request, "alias"), options)
			if err != nil {
				return nil, err
			}
			data := js.Global().Get("Uint8Array").New(len(file.Data))
			js.CopyBytesToJS(data, file.Data)
			return map[string]any{"ok": true, "status": 200, "fileName": file.FileName,
				"contentType": file.ContentType, "data": data}, nil
		})
	}))
	js.Global().Set("sslConverter", api)
	select {}
}

// promise 는 work 를 고루틴에서 실행하고, 패닉이 나도 오류 응답으로 바꿔 돌려준다.
func promise(work func() (map[string]any, error)) js.Value {
	var executor js.Func
	executor = js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve := args[0]
		go func() {
			result, err := func() (result map[string]any, err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("%v", r)
					}
				}()
				return work()
			}()
			if err != nil {
				result = errorResult(err)
			}
			resolve.Invoke(js.ValueOf(result))
		}()
		return nil
	})
	defer executor.Release()
	return js.Global().Get("Promise").New(executor)
}

// errorResult 는 Java 판 ApiExceptionHandler 와 같은 상태 코드와 메시지를 만든다.
func errorResult(err error) map[string]any {
	var conversion *cert.ConversionError
	if errors.As(err, &conversion) {
		return map[string]any{"ok": false, "status": 400, "message": conversion.Message}
	}
	return map[string]any{"ok": false, "status": 500, "message": "처리 중 오류가 발생했습니다: " + err.Error()}
}

func sources(request js.Value) []cert.InputSource {
	var result []cert.InputSource
	files := request.Get("files")
	for i := 0; i < files.Length(); i++ {
		file := files.Index(i)
		data := make([]byte, file.Get("data").Length())
		js.CopyBytesToGo(data, file.Get("data"))
		if len(data) > 0 {
			result = append(result, cert.InputSource{Name: file.Get("name").String(), Data: data})
		}
	}
	if text := str(request, "text"); text != "" {
		result = append(result, cert.InputSource{Name: "붙여넣은 텍스트", Data: []byte(text)})
	}
	return result
}

func exportOptions(request js.Value) (cert.ExportOptions, error) {
	options := cert.ExportOptions{
		Formats:     map[string]bool{},
		BaseName:    str(request, "baseName"),
		Alias:       str(request, "outAlias"),
		Password:    str(request, "outPassword"),
		IncludeRoot: str(request, "includeRoot") != "false",
		LegacyPfx:   str(request, "legacyPfx") == "true",
		KeyFormat:   cert.KeyFormat(str(request, "keyFormat")),
	}
	switch options.KeyFormat {
	case "", cert.KeyPKCS8, cert.KeyTraditional, cert.KeyPKCS8Encrypted:
	default:
		return options, &cert.ConversionError{Message: "알 수 없는 개인키 형식입니다: " + string(options.KeyFormat)}
	}
	formats := request.Get("formats")
	for i := 0; i < formats.Length(); i++ {
		id := formats.Index(i).String()
		if _, ok := cert.FormatByID(id); !ok {
			return options, &cert.ConversionError{Message: "알 수 없는 출력 형식입니다: " + id}
		}
		options.Formats[id] = true
	}
	return options, nil
}

func str(request js.Value, name string) string {
	value := request.Get(name)
	if value.IsUndefined() || value.IsNull() {
		return ""
	}
	return value.String()
}
