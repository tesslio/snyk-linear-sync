package model

// CreateOutcome binds an input alias to its returned issue. Acknowledged is
// true only for a successful alias with a nonempty ID. An error accompanying
// outcomes makes unacknowledged entries uncertain, not safe retry candidates.
type CreateOutcome struct {
	Index        int    `json:"index"`
	ID           string `json:"id"`
	Identifier   string `json:"identifier"`
	Acknowledged bool   `json:"acknowledged"`
}
