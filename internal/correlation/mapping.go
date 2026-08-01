package correlation

import "strings"

// sdkToIAMAction maps SDK operation names that differ from their canonical IAM action names.
// Key: "service:SDKOperation" (lowercase service prefix).
// Value: correct IAM action "service:IAMAction".
// Identity mappings (key == value) are omitted; the lookup falls through to
// returning the input unchanged, which is equivalent.
var sdkToIAMAction = map[string]string{
	// Lambda SDK uses short names; IAM requires the full name.
	"lambda:invoke":              "lambda:InvokeFunction",
	"lambda:invokeasync":         "lambda:InvokeFunction",
	"lambda:invokewithqualifier": "lambda:InvokeFunction",

	// S3 HEAD operations map to the corresponding IAM permission.
	"s3:headobject": "s3:GetObject",
	"s3:headbucket": "s3:ListBucket",

	// EC2 SDK operations use singular names; IAM uses plural names.
	"ec2:startinstance": "ec2:StartInstances",
	"ec2:stopinstance":  "ec2:StopInstances",
}

// MapSDKToIAM converts an SDK-observed privilege to its canonical IAM action name.
// If no mapping exists, the input is returned unchanged.
// Input format: "service:Operation" (service is already lowercase).
func MapSDKToIAM(privilege string) string {
	if mapped, ok := sdkToIAMAction[strings.ToLower(privilege)]; ok {
		return mapped
	}
	return privilege
}
