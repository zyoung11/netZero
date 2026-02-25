package texts

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/cursor"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

var (
	focusedStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cursorStyle         = focusedStyle
	noStyle             = lipgloss.NewStyle()
	helpStyle           = blurredStyle
	cursorModeHelpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	focusedButton = focusedStyle.Render("[ Submit ]")
	blurredButton = fmt.Sprintf("[ %s ]", blurredStyle.Render("Submit"))
)

type InputConfig struct {
	Placeholder   string
	CharLimit     int
	EchoMode      textinput.EchoMode
	EchoCharacter rune
}

type TextInputsConfig struct {
	Inputs []InputConfig
}

type model struct {
	focusIndex int
	inputs     []textinput.Model
	cursorMode cursor.Mode
	submitted  bool
}

func TextInputs(config TextInputsConfig) []string {
	m := initialModel(config)
	p := tea.NewProgram(m)
	finalModel, err := p.Run()
	if err != nil {
		panic(err)
	}
	if m, ok := finalModel.(model); ok && m.submitted {
		results := make([]string, len(m.inputs))
		for i, input := range m.inputs {
			results[i] = input.Value()
		}
		return results
	}

	return nil
}

func initialModel(config TextInputsConfig) model {
	inputCount := len(config.Inputs)
	m := model{
		inputs: make([]textinput.Model, inputCount),
	}

	for i := range m.inputs {
		t := textinput.New()

		t.SetWidth(30)

		cfg := config.Inputs[i]
		t.Placeholder = cfg.Placeholder

		if cfg.CharLimit > 0 {
			t.CharLimit = cfg.CharLimit
		} else {
			t.CharLimit = 32
		}

		if cfg.EchoMode != 0 {
			t.EchoMode = cfg.EchoMode
			if cfg.EchoCharacter != 0 {
				t.EchoCharacter = cfg.EchoCharacter
			} else {
				t.EchoCharacter = '•'
			}
		}

		s := t.Styles()
		s.Cursor.Color = lipgloss.Color("205")
		s.Focused.Prompt = focusedStyle
		s.Focused.Text = focusedStyle
		s.Blurred.Prompt = blurredStyle
		s.Blurred.Text = blurredStyle
		t.SetStyles(s)

		if i == 0 {
			t.Focus()
		}

		m.inputs[i] = t
	}

	return m
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit

		case "ctrl+r":
			m.cursorMode++
			if m.cursorMode > cursor.CursorHide {
				m.cursorMode = cursor.CursorBlink
			}
			cmds := make([]tea.Cmd, len(m.inputs))
			for i := range m.inputs {
				s := m.inputs[i].Styles()
				s.Cursor.Blink = m.cursorMode == cursor.CursorBlink
				m.inputs[i].SetStyles(s)
			}
			return m, tea.Batch(cmds...)

		case "tab", "shift+tab", "enter", "up", "down":
			s := msg.String()

			if s == "enter" && m.focusIndex == len(m.inputs) {
				m.submitted = true
				return m, tea.Quit
			}

			if s == "up" || s == "shift+tab" {
				m.focusIndex--
			} else {
				m.focusIndex++
			}

			if m.focusIndex > len(m.inputs) {
				m.focusIndex = 0
			} else if m.focusIndex < 0 {
				m.focusIndex = len(m.inputs)
			}

			cmds := make([]tea.Cmd, len(m.inputs))
			for i := 0; i <= len(m.inputs)-1; i++ {
				if i == m.focusIndex {
					cmds[i] = m.inputs[i].Focus()
					continue
				}
				m.inputs[i].Blur()
			}

			return m, tea.Batch(cmds...)
		}
	}

	cmd := m.updateInputs(msg)

	return m, cmd
}

func (m *model) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))
	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}
	return tea.Batch(cmds...)
}

func (m model) View() tea.View {
	var b strings.Builder
	var c *tea.Cursor

	for i, in := range m.inputs {
		b.WriteString(m.inputs[i].View())
		if i < len(m.inputs)-1 {
			b.WriteRune('\n')
		}
		if m.cursorMode != cursor.CursorHide && in.Focused() {
			c = in.Cursor()
			if c != nil {
				c.Y += i
			}
		}
	}

	button := &blurredButton
	if m.focusIndex == len(m.inputs) {
		button = &focusedButton
	}
	fmt.Fprintf(&b, "\n\n%s\n\n", *button)

	b.WriteString(helpStyle.Render("cursor mode is "))
	b.WriteString(cursorModeHelpStyle.Render(m.cursorMode.String()))
	b.WriteString(helpStyle.Render(" (ctrl+r to change style)"))

	v := tea.NewView(b.String())
	v.Cursor = c
	return v
}

// 教程
// package main

// import (
// 	"fmt"
// 	"main/texts"

// 	"charm.land/bubbles/v2/textinput"
// )

// func main() {
// 	config := texts.TextInputsConfig{
// 		Inputs: []texts.InputConfig{
// 			{Placeholder: "Name"},
// 			{Placeholder: "Email", CharLimit: 64},
// 			{Placeholder: "Password", EchoMode: textinput.EchoPassword},
// 		},
// 	}

// 	result := texts.TextInputs(config)

// 	if result != nil {
// 		fmt.Println("\n--- Submitted Values ---")
// 		fmt.Printf("Name:     %s\n", result[0])
// 		fmt.Printf("Email:    %s\n", result[1])
// 		fmt.Printf("Password: %s\n", result[2])
// 	} else {
// 		fmt.Println("\nOperation cancelled.")
// 	}
// }
