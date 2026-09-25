package redact_test

import (
	"fmt"

	"github.com/peasant-labs/redact"
)

func ExampleNewRun() {
	engine, err := redact.NewRedactor(redact.Standard, nil, redact.XDGPaths{})
	if err != nil {
		panic(err)
	}
	run, err := redact.NewRun(engine, "batch-17", func(o redact.Observation) error {
		fmt.Printf("run=%s call=%s detected=%d duration_recorded=%t\n", o.RunID, o.CorrelationID, o.RegexDetected.Value, o.Duration >= 0)
		return nil
	})
	if err != nil {
		panic(err)
	}
	output, delivery := run.RedactText("item-42", "hello")
	fmt.Println(output, delivery == redact.DeliveryOK)
	// Output:
	// run=batch-17 call=item-42 detected=0 duration_recorded=true
	// hello true
}
