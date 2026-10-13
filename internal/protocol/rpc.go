package protocol

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const Version = "2025-11-25"

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type Call struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

func Read(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func Fail(w http.ResponseWriter, id json.RawMessage, status int, reason string) {
	JSON(w, status, Response{JSONRPC: "2.0", ID: id, Error: &Error{-32001, reason}})
}
func Success(w http.ResponseWriter, id json.RawMessage, result any) {
	JSON(w, 200, Response{JSONRPC: "2.0", ID: id, Result: result})
}
