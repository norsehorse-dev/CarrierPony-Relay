// Package push wakes devices with this relay's own APNs and FCM credentials.
// A push never carries a sender or any content: the relay cannot read an
// envelope, and nothing here is derived from one.
package push

// Shape is what a push looks like for one deposit, on each platform. It depends
// only on two things the sender states: whether the deposit is silent, and
// whether it is a contact request.
type Shape struct {
	APNsPayload  string
	APNsType     string
	APNsPriority int
	// FCMData is sent in order, as pairs, so the request body is the same
	// every time.
	FCMData [][2]string
}

// ShapeFor returns the push for a deposit.
//
// A real message gets the alert banner. content-available is set too, so the
// app can fetch in the background. A silent send (a control message or a copy
// to the sender's own devices) gets a background wake only, so the app syncs
// without a "New message" the user opens to find nothing behind. A contact
// request gets a banner that says so and never who: on iOS by a key the app
// translates, with plain English for an app that does not have the key; on
// Android by a field the app reads.
func ShapeFor(silent bool, kind string) Shape {
	if silent {
		return Shape{
			APNsPayload:  `{"aps":{"content-available":1}}`,
			APNsType:     "background",
			APNsPriority: 5,
			FCMData:      [][2]string{{"wake", "1"}, {"silent", "1"}},
		}
	}
	if kind == "request" {
		return Shape{
			APNsPayload: `{"aps":{"alert":{"title":"CarrierPony","body":"Someone wants to connect.",` +
				`"loc-key":"Someone wants to connect. Tap to review."},"sound":"default","content-available":1}}`,
			APNsType:     "alert",
			APNsPriority: 10,
			FCMData:      [][2]string{{"wake", "1"}, {"kind", "request"}},
		}
	}
	return Shape{
		APNsPayload:  `{"aps":{"alert":{"title":"CarrierPony","body":"New message"},"sound":"default","content-available":1}}`,
		APNsType:     "alert",
		APNsPriority: 10,
		FCMData:      [][2]string{{"wake", "1"}},
	}
}
