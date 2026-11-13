package tools

// Result mirrors the JSON contract returned by the Spring tools API.
type Result struct {
	Messages []string  `json:"messages"`
	Sections []Section `json:"sections"`
	Files    []Artifact `json:"files"`
	Tree     any        `json:"tree,omitempty"`
}

type Section struct {
	Title string `json:"title"`
	Level string `json:"level"`
	Rows  []Row  `json:"rows"`
}

type Row struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type Artifact struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

func section(title, level string, pairs ...string) Section {
	rows := make([]Row, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		rows = append(rows, Row{Label: pairs[i], Value: pairs[i+1]})
	}
	return Section{Title: title, Level: level, Rows: rows}
}
