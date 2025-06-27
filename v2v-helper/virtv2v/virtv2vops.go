// Copyright © 2024 The vjailbreak authors

package virtv2v

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/platform9/vjailbreak/v2v-helper/vm"
)

//go:generate mockgen -source=../virtv2v/virtv2vops.go -destination=../virtv2v/virtv2vops_mock.go -package=virtv2v

type VirtV2VOperations interface {
	RetainAlphanumeric(input string) string
	GetPartitions(disk string) ([]string, error)
	NTFSFix(path string) error
	ConvertDisk(ctx context.Context, path, ostype, virtiowindriver string, firstbootscripts []string, useSingleDisk bool, diskPath string) error
	AddWildcardNetplan(path string) error
	GetOsRelease(path string) (string, error)
	AddFirstBootScript(firstbootscript, firstbootscriptname string) error
}

func RetainAlphanumeric(input string) string {
	var builder strings.Builder
	for _, char := range input {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

func GetPartitions(disk string) ([]string, error) {
	// Execute lsblk command to get partition information
	cmd := exec.Command("lsblk", "-no", "NAME", disk)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to execute lsblk: %w", err)
	}

	var partitions []string
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && line != disk {
			partitions = append(partitions, "/dev/"+RetainAlphanumeric(line))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading lsblk output: %w", err)
	}

	return partitions, nil
}

func NTFSFix(path string) error {
	// Fix NTFS
	partitions, err := GetPartitions(path)
	if err != nil {
		return fmt.Errorf("failed to get partitions: %w", err)
	}
	log.Printf("Partitions: %v", partitions)
	for _, partition := range partitions {
		if partition == path {
			continue
		}
		cmd := exec.Command("ntfsfix", partition)
		log.Printf("Executing %s", cmd.String())

		err := cmd.Run()
		if err != nil {
			log.Printf("Skipping NTFS fix on %s", partition)
		}
		log.Printf("Fixed NTFS on %s", partition)
	}
	return nil
}

type TimingResult struct {
	FirstCopyTime     time.Duration
	IncrementalCopies []time.Duration
	TotalTime         time.Duration
}

var timings TimingResult

func downloadFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download file: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	out, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func ConvertDisk(ctx context.Context, diskPath, xmlFile string, isWindows bool, driverURL string) error {
	if isWindows {
		log.Println("Downloading Windows virtio driver...")
		if err := downloadFile(driverURL, "/tmp/virtio.iso"); err != nil {
			return err
		}
		defer os.Remove("/tmp/virtio.iso")
		os.Setenv("VIRTIO_WIN", "/tmp/virtio.iso")
	}
	os.Setenv("LIBGUESTFS_BACKEND", "direct")
	args := []string{"-i", "libvirtxml", xmlFile, "--root", "/dev/sda1"}
	start := time.Now()
	cmd := exec.CommandContext(ctx, "virt-v2v-in-place", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("conversion failed: %v", err)
	}
	timings.FirstCopyTime = time.Since(start)
	log.Printf("Disk conversion done in: %s", timings.FirstCopyTime)
	return nil
}

func PerformIncrementalCopy(iteration int) {
	start := time.Now()
	log.Printf("Incremental copy #%d started...", iteration)
	time.Sleep(1 * time.Second)
	duration := time.Since(start)
	timings.IncrementalCopies = append(timings.IncrementalCopies, duration)
	log.Printf("Incremental copy #%d done in: %s", iteration, duration)
}

func ShowSummary() {
	timings.TotalTime = timings.FirstCopyTime
	log.Printf("First Block Copy Time: %s", timings.FirstCopyTime)
	for i, t := range timings.IncrementalCopies {
		log.Printf("Incremental Copy #%d: %s", i+1, t)
		timings.TotalTime += t
	}
	log.Printf("Total Conversion Time: %s", timings.TotalTime)
}

func CheckForVirtioDrivers() (bool, error) {

	// Before downloading virtio windrivers Check if iso is present in the path
	preDownloadPath := "/home/fedora/virtio-win"

	// Check if path exists
	_, err := os.Stat(preDownloadPath)
	if err != nil {
		return false, fmt.Errorf("failed to check if path exists: %s", err)
	}
	// Check if iso is present in the path
	files, err := os.ReadDir(preDownloadPath)
	if err != nil {
		return false, fmt.Errorf("failed to read directory: %s", err)
	}
	for _, file := range files {
		if file.Name() == "virtio-win.iso" {
			log.Println("Found virtio windrivers")
			return true, nil
		}
	}
	return false, nil
}

func GetOsRelease(path string) (string, error) {
	// Get the os-release file
	os.Setenv("LIBGUESTFS_BACKEND", "direct")
	cmd := exec.Command(
		"guestfish",
		"--ro",
		"-a",
		path,
		"-i")
	input := `cat /etc/os-release`
	cmd.Stdin = strings.NewReader(input)
	log.Printf("Executing %s", cmd.String()+" "+input)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get os-release: %s, %s", out, err)
	}
	return strings.ToLower(string(out)), nil
}

func AddWildcardNetplan(disks []vm.VMDisk, useSingleDisk bool, diskPath string) error {
	// Add wildcard to netplan
	var ans string
	netplan := `[Match]
Name=en*

[Network]
DHCP=yes`

	// Create the netplan file
	err := os.WriteFile("/home/fedora/99-wildcard.network", []byte(netplan), 0644)
	if err != nil {
		return fmt.Errorf("failed to create netplan file: %s", err)
	}
	log.Println("Created local netplan file")
	log.Println("Uploading netplan file to disk")
	// Upload it to the disk
	os.Setenv("LIBGUESTFS_BACKEND", "direct")
	if useSingleDisk {
		command := `upload /home/fedora/99-wildcard.network /etc/systemd/network/99-wildcard.network`
		ans, err = RunCommandInGuest(diskPath, command, true)
	} else {
		command := "upload"
		ans, err = RunCommandInGuestAllVolumes(disks, command, true, "/home/fedora/99-wildcard.network", "/etc/systemd/network/99-wildcard.network")
	}
	if err != nil {
		fmt.Printf("failed to run command (%s): %v: %s\n", "upload", err, strings.TrimSpace(ans))
		return err
	}
	return nil
}

func AddFirstBootScript(firstbootscript, firstbootscriptname string) error {
	// Create the firstboot script
	firstbootscriptpath := fmt.Sprintf("/home/fedora/%s.sh", firstbootscriptname)
	err := os.WriteFile(firstbootscriptpath, []byte(firstbootscript), 0644)
	if err != nil {
		return fmt.Errorf("failed to create firstboot script: %s", err)
	}
	log.Printf("Created firstboot script %s", firstbootscriptname)
	return nil
}

// Runs command inside temporary qemu-kvm that virt-v2v creates
func RunCommandInGuest(path string, command string, write bool) (string, error) {
	os.Setenv("LIBGUESTFS_BACKEND", "direct")
	option := "--ro"
	if write {
		option = "--rw"
	}
	cmd := exec.Command(
		"guestfish",
		option,
		"-a",
		path,
		"-i")
	cmd.Stdin = strings.NewReader(command)
	log.Printf("Executing %s", cmd.String()+" "+command)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run command (%s): %v: %s", command, err, strings.TrimSpace(string(out)))
	}
	return strings.ToLower(strings.TrimSpace(string(out))), nil
}

// Runs command inside temporary qemu-kvm that virt-v2v creates
func CheckForLVM(disks []vm.VMDisk) (string, error) {
	os.Setenv("LIBGUESTFS_BACKEND", "direct")

	// Get the installed os info
	command := "inspect-os"
	osPath, err := RunCommandInGuestAllVolumes(disks, command, false)
	if err != nil {
		return "", fmt.Errorf("failed to run command (%s): %v: %s", command, err, strings.TrimSpace(osPath))
	}

	// Get the lvs list
	command = "lvs"
	lvsStr, err := RunCommandInGuestAllVolumes(disks, command, false)
	if err != nil {
		return "", fmt.Errorf("failed to run command (%s): %v: %s", command, err, strings.TrimSpace(lvsStr))
	}

	lvs := strings.Split(string(lvsStr), "\n")
	if slices.Contains(lvs, strings.TrimSpace(string(osPath))) {
		return string(strings.TrimSpace(string(osPath))), nil
	}

	return "", fmt.Errorf("LVM not found: %v, %d", lvs, len(lvs))
}

func prepareGuestfishCommand(disks []vm.VMDisk, command string, write bool, args ...string) *exec.Cmd {
	option := "--ro"
	if write {
		option = "--rw"
	}
	cmd := exec.Command(
		"guestfish",
		option)

	for _, disk := range disks {
		cmd.Args = append(cmd.Args, "-a", disk.Path)
	}
	cmd.Args = append(cmd.Args, "-i", command)
	cmd.Args = append(cmd.Args, args...)
	return cmd
}

func RunCommandInGuestAllVolumes(disks []vm.VMDisk, command string, write bool, args ...string) (string, error) {
	os.Setenv("LIBGUESTFS_BACKEND", "direct")
	cmd := prepareGuestfishCommand(disks, command, write, args...)
	log.Printf("Executing %s", cmd.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to run command (%s): %v: %s", command, err, strings.TrimSpace(string(out)))
	}
	return strings.ToLower(string(out)), nil
}

func GetBootableVolumeIndex(disks []vm.VMDisk) (int, error) {
	command := "list-partitions"
	partitionsStr, err := RunCommandInGuestAllVolumes(disks, command, false)
	if err != nil {
		return -1, fmt.Errorf("failed to run command (%s): %v: %s", command, err, strings.TrimSpace(partitionsStr))
	}

	partitions := strings.Split(strings.TrimSpace(partitionsStr), "\n")
	for _, partition := range partitions {
		command := "part-to-dev"
		device, err := RunCommandInGuestAllVolumes(disks, command, false, strings.TrimSpace(partition))
		if err != nil {
			fmt.Printf("failed to run command (%s): %v: %s\n", device, err, strings.TrimSpace(device))
			return -1, err
		}

		command = "part-to-partnum"
		num, err := RunCommandInGuestAllVolumes(disks, command, false, strings.TrimSpace(partition))
		if err != nil {
			fmt.Printf("failed to run command (%s): %v: %s\n", num, err, strings.TrimSpace(num))
			return -1, err
		}

		command = "part-get-bootable"
		bootable, err := RunCommandInGuestAllVolumes(disks, command, false, strings.TrimSpace(device), strings.TrimSpace(num))
		if err != nil {
			fmt.Printf("failed to run command (%s): %v: %s\n", bootable, err, strings.TrimSpace(bootable))
			return -1, err
		}

		if strings.TrimSpace(bootable) == "true" {
			command = "device-index"
			index, err := RunCommandInGuestAllVolumes(disks, command, false, strings.TrimSpace(device))
			if err != nil {
				fmt.Printf("failed to run command (%s): %v: %s\n", index, err, strings.TrimSpace(index))
				return -1, err
			}
			return strconv.Atoi(strings.TrimSpace(index))
		}
	}
	return -1, errors.New("bootable volume not found")
}
