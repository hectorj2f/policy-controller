package webhook

type VerificationTuple struct {
	PolicyName      string
	Image           string
	ResourceVersion string
	PolicyResult    *PolicyResult
	Errors          []error
	Warnings        []error
	Pass            bool
}
