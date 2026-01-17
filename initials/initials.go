package initials

import (
	"github.com/digitorus/pdfsign/internal/render"
)

// Config represents configuration for initials on all pages.
type Config struct {
	Appearance   *render.AppearanceInfo
	Position     int // Use int to avoid circularity if possible, or define type here
	MarginX      float64
	MarginY      float64
	ExcludePages []int
}

// Position defines the corner for initials.
type Position int

const (
	// TopLeft positions at top-left corner.
	TopLeft Position = iota
	// TopRight positions at top-right corner.
	TopRight
	// BottomLeft positions at bottom-left corner.
	BottomLeft
	// BottomRight positions at bottom-right corner.
	BottomRight
)

// Builder builds initials configuration.
type Builder struct {
	Config *Config
}

// Position sets the position for initials.
func (b *Builder) Position(pos Position, marginX, marginY float64) *Builder {
	b.Config.Position = int(pos)
	b.Config.MarginX = marginX
	b.Config.MarginY = marginY
	return b
}

// ExcludePages excludes specific pages from initials.
func (b *Builder) ExcludePages(pages ...int) *Builder {
	b.Config.ExcludePages = pages
	return b
}
