package client

// nowMillis is isolated for tests.
var nowMillisFunc = func() int64 { return testNow }

var testNow int64 = 1750000000000

func nowMillis() int64 {
	if nowMillisFunc != nil {
		return nowMillisFunc()
	}
	return testNow
}
