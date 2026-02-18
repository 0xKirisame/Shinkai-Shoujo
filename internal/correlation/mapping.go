package correlation

// sdkToIAMAction maps SDK operation names that differ from their canonical IAM action names.
// Key: "service:SDKOperation" (lowercase service prefix).
// Value: correct IAM action "service:IAMAction".
// Identity mappings (key == value) are omitted — the lookup falls through to
// returning the input unchanged, which is equivalent.
var sdkToIAMAction = map[string]string{
	// Lambda — SDK uses short names; IAM requires the full name.
	"lambda:Invoke":              "lambda:InvokeFunction",
	"lambda:InvokeAsync":         "lambda:InvokeFunction",
	"lambda:InvokeWithQualifier": "lambda:InvokeFunction",

	// S3 — HEAD operations map to the corresponding IAM permission.
	"s3:HeadObject": "s3:GetObject",
	"s3:HeadBucket": "s3:ListBucket",

	// EC2 — SDK uses singular; IAM uses plural.
	"ec2:StartInstance": "ec2:StartInstances",
	"ec2:StopInstance":  "ec2:StopInstances",
}

// MapSDKToIAM converts an SDK-observed privilege to its canonical IAM action name.
// If no mapping exists, the input is returned unchanged.
// Input format: "service:Operation" (service is already lowercase).
func MapSDKToIAM(privilege string) string {
	if mapped, ok := sdkToIAMAction[privilege]; ok {
		return mapped
	}
	return privilege
}
