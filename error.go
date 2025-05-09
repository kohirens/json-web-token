package jwt

type ErrInvalidFmt struct {
	message string
}

func (e *ErrInvalidFmt) Error() string {
	return e.message
}

type ErrMissingClaim struct {
	claim string
}

func (e *ErrMissingClaim) Error() string {
	return "missing claim " + e.claim
}
