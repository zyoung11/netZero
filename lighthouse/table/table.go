package table

import (
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
)

type TableConfig struct {
	Headers []string
	Rows    [][]string
}

func ShowTable(config TableConfig) []string {
	m := model{
		config:   config,
		cursor:   0,
		quitting: false,
		selected: false,
	}

	m.rebuildTable()

	p := tea.NewProgram(m)
	finalModel, err := p.Run()
	if err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}

	if m, ok := finalModel.(model); ok && m.selected {
		return m.config.Rows[m.cursor]
	}

	return nil
}

type model struct {
	config   TableConfig
	table    *table.Table
	cursor   int
	selected bool
	quitting bool
	width    int
	height   int
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.rebuildTable()
		return m, nil

	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		case "enter":
			m.selected = true
			return m, tea.Quit
		case "down", "j":
			if m.cursor < len(m.config.Rows)-1 {
				m.cursor++
				m.rebuildTable()
			}
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.rebuildTable()
			}
		}
	}
	return m, nil
}

func (m model) View() tea.View {
	v := tea.NewView("\n" + m.table.String() + "\n")
	v.AltScreen = true
	return v
}

func (m *model) rebuildTable() {
	baseStyle := lipgloss.NewStyle().Padding(0, 1)
	headerStyle := baseStyle.Foreground(lipgloss.Color("15")).Bold(true).Background(lipgloss.Color("240"))
	selectedStyle := baseStyle.Foreground(lipgloss.Color("0")).Background(lipgloss.Color("247")).Bold(true)
	evenRowStyle := baseStyle.Foreground(lipgloss.Color("7"))
	oddRowStyle := baseStyle.Foreground(lipgloss.Color("15"))

	rows := m.config.Rows
	cursor := m.cursor

	t := table.New().
		Headers(m.config.Headers...).
		Rows(rows...).
		Border(lipgloss.NormalBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("240"))).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == -1 {
				return headerStyle
			}

			rowIndex := row
			if rowIndex < 0 || rowIndex >= len(rows) {
				return baseStyle
			}

			if rowIndex == cursor {
				return selectedStyle
			}

			if row%2 == 0 {
				return evenRowStyle
			}
			return oddRowStyle
		})

	if m.width > 0 {
		t = t.Width(m.width)
	}
	if m.height > 0 {
		t = t.Height(m.height)
	}

	m.table = t
}

// 教程
// package main

// import (
// 	"fmt"
// 	"main/table"
// )

// func main() {
// 	headers := []string{"#", "NAME", "TYPE 1", "TYPE 2", "JAPANESE", "OFFICIAL ROM."}
// 	rows := [][]string{
// 		{"1", "Bulbasaur", "Grass", "Poison", "フシギダネ", "Bulbasaur"},
// 		{"2", "Ivysaur", "Grass", "Poison", "フシギソウ", "Ivysaur"},
// 		{"3", "Venusaur", "Grass", "Poison", "フシギバナ", "Venusaur"},
// 		{"4", "Charmander", "Fire", "", "ヒトカゲ", "Hitokage"},
// 		{"5", "Charmeleon", "Fire", "", "リザード", "Lizardo"},
// 		{"6", "Charizard", "Fire", "Flying", "リザードン", "Lizardon"},
// 		{"7", "Squirtle", "Water", "", "ゼニガメ", "Zenigame"},
// 		{"8", "Wartortle", "Water", "", "カメール", "Kameil"},
// 		{"9", "Blastoise", "Water", "", "カメックス", "Kamex"},
// 		{"10", "Caterpie", "Bug", "", "キャタピー", "Caterpie"},
// 		{"25", "Pikachu", "Electric", "", "ピカチュウ", "Pikachu"},
// 	}

// 	config := table.TableConfig{
// 		Headers: headers,
// 		Rows:    rows,
// 	}

// 	result := table.ShowTable(config)

// 	if result != nil {
// 		fmt.Println("\n--- You Selected ---")
// 		fmt.Printf("Name: %s (%s)\n", result[1], result[5])
// 	} else {
// 		fmt.Println("\nOperation cancelled.")
// 	}
// }
