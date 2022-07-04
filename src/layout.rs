#![allow(dead_code)] 

pub enum Layout {
    LeftAligned,
    RightAligned,
    Centered,
}
#[derive(Copy, Clone)]
pub enum Line {
    First = 22,
    Second = 42,
    Third = 62,
}

pub trait Displayable {
    fn display_pad(&self, line: Line, layout: Layout, padding: i32);
    fn display(&self, line: Line, layout: Layout) {
        self.display_pad(line, layout, 0)
    }
}
