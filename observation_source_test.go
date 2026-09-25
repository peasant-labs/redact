package redact

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"
)

func TestObservationDisabledForwarding(t *testing.T) {
	rows, err := loadObservationAllocationFixtures()
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "observation.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			args := "input"
			switch row.Operation {
			case "Redact":
				args = "input, matches"
			case "RedactJSON":
				args = "value"
			case "RedactMetadata":
				args = "meta"
			}
			source := fmt.Sprintf("package redact; func check(){ if r.observer == nil { return r.legacy.%s(%s), DeliveryDisabled } }", row.Operation, args)
			wantFile, err := parser.ParseFile(fset, "expected.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			var want bytes.Buffer
			if err := printer.Fprint(&want, fset, wantFile.Decls[0].(*ast.FuncDecl).Body.List[0]); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != row.Operation || fn.Recv == nil {
					continue
				}
				receiver, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				name, ok := receiver.X.(*ast.Ident)
				if !ok || name.Name != "Run" {
					continue
				}
				found = true
				if len(fn.Body.List) == 0 {
					t.Fatal("empty Run method")
				}
				var got bytes.Buffer
				if err := printer.Fprint(&got, fset, fn.Body.List[0]); err != nil {
					t.Fatal(err)
				}
				if got.String() != want.String() {
					t.Fatalf("disabled first branch must directly forward unchanged arguments\ngot %s\nwant %s", got.String(), want.String())
				}
			}
			if !found {
				t.Fatal("public Run operation missing")
			}
		})
	}
}
