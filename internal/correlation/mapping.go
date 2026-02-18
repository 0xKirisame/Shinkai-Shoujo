package correlation

import "strings"

// sdkToIAMAction maps known SDK operation names that differ from IAM action names.
// Key: normalized "service:SDKOperation" (lowercase service, original-case operation).
// Value: correct IAM action "service:IAMAction".
var sdkToIAMAction = map[string]string{
	// Lambda
	"lambda:Invoke":              "lambda:InvokeFunction",
	"lambda:InvokeAsync":         "lambda:InvokeFunction",
	"lambda:InvokeWithQualifier": "lambda:InvokeFunction",

	// S3
	"s3:HeadObject":  "s3:GetObject",
	"s3:HeadBucket":  "s3:ListBucket",
	"s3:CreateBucket": "s3:CreateBucket", // already correct, explicit for clarity

	// EC2
	"ec2:RunInstances":  "ec2:RunInstances",  // correct
	"ec2:StartInstance": "ec2:StartInstances", // plural in IAM
	"ec2:StopInstance":  "ec2:StopInstances",  // plural in IAM

	// STS
	"sts:AssumeRoleWithWebIdentity": "sts:AssumeRoleWithWebIdentity",
	"sts:GetCallerIdentity":         "sts:GetCallerIdentity",

	// DynamoDB
	"dynamodb:BatchGetItem":  "dynamodb:BatchGetItem",
	"dynamodb:BatchWriteItem": "dynamodb:BatchWriteItem",

	// Kinesis
	"kinesis:PutRecord":  "kinesis:PutRecord",
	"kinesis:PutRecords": "kinesis:PutRecords",

	// CloudWatch
	"cloudwatch:PutMetricData": "cloudwatch:PutMetricData",

	// SNS
	"sns:Publish": "sns:Publish",

	// SQS
	"sqs:SendMessage":        "sqs:SendMessage",
	"sqs:ReceiveMessage":     "sqs:ReceiveMessage",
	"sqs:DeleteMessage":      "sqs:DeleteMessage",
	"sqs:ChangeMessageVisibility": "sqs:ChangeMessageVisibility",
}

// MapSDKToIAM converts an SDK-observed privilege to its canonical IAM action name.
// If no mapping exists, the input is returned unchanged.
// Input format: "service:Operation" (service is already lowercase).
func MapSDKToIAM(privilege string) string {
	if mapped, ok := sdkToIAMAction[privilege]; ok {
		return mapped
	}
	// Also try with lowercase operation for case-insensitive matching
	parts := strings.SplitN(privilege, ":", 2)
	if len(parts) == 2 {
		key := parts[0] + ":" + parts[1]
		if mapped, ok := sdkToIAMAction[key]; ok {
			return mapped
		}
	}
	return privilege
}
