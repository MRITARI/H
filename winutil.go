package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

func hiddenProc(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

type shFileOp struct {
	Hwnd         uintptr
	Func         uint32
	From, To     *uint16
	Flags        uint16
	AnyAborted   int32
	NameMappings uintptr
	Title        *uint16
}

// recycle moves a path to the Recycle Bin (undoable).
func recycle(path string) error {
	from, err := syscall.UTF16FromString(path)
	if err != nil {
		return err
	}
	from = append(from, 0) // double-NUL terminated
	op := shFileOp{
		Func:  3, // FO_DELETE
		From:  &from[0],
		Flags: 0x40 | 0x10 | 0x4 | 0x400, // ALLOWUNDO|NOCONFIRMATION|SILENT|NOERRORUI
	}
	r, _, _ := syscall.NewLazyDLL("shell32.dll").NewProc("SHFileOperationW").Call(uintptr(unsafe.Pointer(&op)))
	if r != 0 || op.AnyAborted != 0 {
		return fmt.Errorf("recycle failed (code 0x%x) - file in use or access denied", r)
	}
	return nil
}

func permanentDelete(path string) error { return os.RemoveAll(path) }

func openInExplorer(path string) { _ = exec.Command("explorer", "/select,"+path).Start() }
