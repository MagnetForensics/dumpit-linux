//
//  Copyright (c) Magnet Forensics, Inc. All rights reserved.
//
// Module Name:
//  main.rs
//
// Abstract:
//  DumpIt for Linux.
//  This leverages /proc/kcore and creates a ELF core dump of the system image.
// 
//  The generated image is compatible with Comae, gdb and crash.
//  This version is a rewritten version from the C++ version.
//
//  sudo ./DumpItForLinux dumpit.$(uname -r).$(date +%F-%H%M).core
//
//  Thanks to Dave Anderson for his work on crash and libdwarf, and his patience
//  answering my questions.
//
// Author:
//  Matthieu Suiche (msuiche) 25-Sept-2022
//
// Revision History:
//  25-Sept-2022    - Moving to rust.
//    1-May-2019    - Initial C implementation.
//

use std::{fs, io};
use std::io::SeekFrom;
use std::io::prelude::*;
use std::io::BufReader;
use std::{mem, env, cmp};
use std::time::{Instant};

use nix::unistd::Uid;
use nix::sys::utsname::uname;
use tabled::{Tabled, Table, Style};
use byteorder::{ByteOrder, LittleEndian};

use env_logger;
use log::{info, debug, error, LevelFilter};

// object lib
use object::elf::*;
use object::Endianness;
use object::read::elf::{FileHeader, ProgramHeader};
use object::{U32};

use chrono::{Utc, Timelike, Datelike};

use dumpitforlinux::error::{Error, Result};
use indicatif::ProgressBar;
use zstd;
use tar;

use clap::Parser;

/// A program that makes memory analysis for incident response easy, scalable and practical.
#[derive(Parser)]
#[clap(about, long_about = None, author="Copyright (c) 2022, Magnet Forensics, Inc.", version = CRATE_VERSION)]
struct Args {
    /// Write to stdout instead of a file.
    #[clap(short='0', long)]
    to_stdout: bool,
    /// Create a single core dump file instead of a compressed archive.
    #[clap(short, long)]
    raw: bool,
    /// Print extra output while parsing
    #[clap(short, long)]
    verbose: bool,
    /// Path to the output archive or file.
    #[clap(value_name = "Output Path")]
    output_path: Option<String>,
}

const PAGE_SIZE: usize  = 0x1000;
const ELF_ALIGN: usize  = 4;
const BLOCK_SIZE: usize = 0x100000; // 1MB

const PROC_DIR: &str = "/proc/";

const CRATE_VERSION: &'static str =
    concat!(env!("VERGEN_GIT_SEMVER"),
     " (", env!("VERGEN_GIT_COMMIT_TIMESTAMP"), ")");

fn round_up(x: usize, y: usize) -> usize {
    ((x + (y - 1)) / y) * y
}

fn pause() {
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    println!("Press any key to continue...");
    stdout.flush().unwrap();

    // Read a single byte and discard
    let _ = stdin.read(&mut [0u8]).unwrap();
}

#[derive(Tabled, Debug)]
pub struct MemoryRange {
    #[tabled(display_with = "display_u64")]
    pub start_phys_addr:        u64,
    #[tabled(display_with = "display_u64")]
    pub end_phys_addr:          u64,
    #[tabled(display_with = "display_u64")]
    pub memsz:                  u64,

    #[tabled(display_with = "display_u64")]
    pub virt_addr:              u64,
    #[tabled(display_with = "display_u64")]
    pub kcore_file_off:         u64,

    pub out_file_off:           u64,

    pub p_flags:                u32,

    pub is_virtual:             bool,
}

impl MemoryRange {
    pub fn set_file_offset(
        &mut self,
        off: u64
    ) {
        self.out_file_off = off;
    }
}

pub fn display_u64(u: &u64) -> String {
    format!("0x{:x}", u)
}

struct DumpItForLinux {
    pub iomem_ranges:           Vec<MemoryRange>,
    pub mem_ranges:             Vec<MemoryRange>,

    // VMCOREINFO
    pub vmci_size_va:           Option<u64>,
    pub vmci_data_va:           Option<u64>,
    pub vmcoreinfo:             Option<Vec<u8>>,

    // kcore
    pub kcore:                  fs::File,
    pub out_header:             Option<Vec<u8>>
}

impl DumpItForLinux  {
    fn new() -> Result<Self> {

        let mem_ranges = Vec::new();

        if !Uid::effective().is_root() {
            return Err(Error::NixError("You must run this executable with root permissions.".to_string()));
        }

        let kcore = fs::File::open(format!("{}kcore", PROC_DIR))?;
        let iomem_ranges = DumpItForLinux::get_memory_ranges()?;
        let _kallsyms = fs::File::open(format!("{}kallsyms", PROC_DIR))?;

        Ok(DumpItForLinux {
            iomem_ranges,
            mem_ranges,
            // VMCOREINFO
            vmci_size_va: None,
            vmci_data_va: None,
            vmcoreinfo: None,
            // kcore
            kcore,
            out_header: None
        })
    }

    // Initialize the data we need prior writing a new memory dump.
    fn init(&mut self) -> Result<()> {
        self.get_vmcoreinfo_syms()?;
        self.parse_kcore()?;

        Ok(())
    }

    // Read data inside /proc/kcore at a given file offset.
    fn read_offset(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; size];

        // Keep scoped to avoid accidental deadlocks.
        {
            let mut rdr = BufReader::new(&self.kcore);
            rdr.seek(SeekFrom::Start(offset as u64))?;
            rdr.read_exact(&mut buf)?;
        }

        Ok(buf)
    }

    // Read a buffer at a given kernel virtual address.
    fn read_virtual(&self, va: u64, size: usize) -> Result<Vec<u8>> {
        if let Some(fo) = self.va_to_fo(va) {
            return self.read_offset(fo, size);
        }

        let msg = format!("Error while reading at address 0x{:x}", va);
        error!("{}", msg);
        Err(Error::IoError(msg.to_string()))
    }

    #[allow(dead_code)]
    // Read a u64 at a given kernel virtual address
    fn read_virtual_u64(&self, va: u64) -> Result<u64> {
        let vec = self.read_virtual(va, 8)?;
        Ok(LittleEndian::read_u64(&vec))
    }

    // Read a u32 at a given kernel virtual address
    fn read_virtual_u32(&self, va: u64) -> Result<u32> {
        let vec = self.read_virtual(va, 8)?;
        Ok(LittleEndian::read_u32(&vec))
    }

    // Get the physical memory ranges (System RAM) from /proc/iomem
    fn get_memory_ranges() -> Result<Vec<MemoryRange>> {
        let mut iomem_ranges = Vec::new();

        let file = fs::File::open(format!("{}iomem", PROC_DIR))?;
        let reader = BufReader::new(file);
    
        for line in reader.lines() {
            let line = line?;
            if line.contains("System RAM") {
                let part1: Vec<&str> = line.split(" ").collect();
                if part1.len() > 0 {
                    let part2: Vec<&str>  = part1[0].split("-").collect();
                    if part2.len() > 1 {
                        let start_phys_addr = u64::from_str_radix(part2[0], 16)?;
                        let end_phys_addr = u64::from_str_radix(part2[1], 16)? + 1;
                        let memsz = end_phys_addr - start_phys_addr;

                        iomem_ranges.push(MemoryRange {
                            start_phys_addr,
                            end_phys_addr,
                            memsz,
                            is_virtual: false,
                            p_flags: 0,
                            virt_addr: 0,
                            kcore_file_off: 0,
                            out_file_off: 0
                            // program_header: None
                        })
                    }
                }
            }
        }

        if iomem_ranges.len() == 0 {
            return Err(Error::IoError("/proc/iomem has no entries.".to_string()));
        }

        Ok(iomem_ranges)
    }

    // Retrieve the values of vmcoreinfo_data & vmcoreinfo_size inside /proc/kallsyms
    fn get_vmcoreinfo_syms(&mut self) -> Result<()> {
        let file = fs::File::open(format!("{}kallsyms", PROC_DIR))?;
        let reader = BufReader::new(file);
    
        for line in reader.lines() {
            let line = line?;
            if line.contains("vmcoreinfo_data") {
                let part1: Vec<&str> = line.split(" ").collect();
                if part1.len() > 0 {
                    let va = u64::from_str_radix(part1[0], 16)?;
                    self.vmci_data_va = Some(va);
                }
            } else if line.contains("vmcoreinfo_size") {
                let part1: Vec<&str> = line.split(" ").collect();
                if part1.len() > 0 {
                    let va = u64::from_str_radix(part1[0], 16)?;
                    self.vmci_size_va = Some(va);
                }
            }
        }

        if self.vmci_data_va.is_some() && self.vmci_size_va.is_some() {
            info!("vmcoreinfo_size: 0x{:x}", self.vmci_size_va.unwrap_or(0));
            info!("vmcoreinfo_data: 0x{:x}", self.vmci_data_va.unwrap_or(0));
        }

        Ok(())
    }

    // Converts a kernel virtual address into a /proc/kcore file offset.
    fn va_to_fo(&self, va: u64) -> Option<u64> {
        for mem_range in &self.mem_ranges {
            if va >= mem_range.virt_addr && va < (mem_range.virt_addr + mem_range.memsz) {
                let fo = va - mem_range.virt_addr + mem_range.kcore_file_off;
                return Some(fo);
            }
        }

        None
    }

    fn read_vmcoreinfo(&mut self) -> Result<()> {
        let data_va = self.vmci_data_va.unwrap_or(0);
        let size_va = self.vmci_size_va.unwrap_or(0);

        if data_va != 0 && size_va != 0 {
            let size = self.read_virtual_u32(size_va)? as usize;
            let data = self.read_virtual(data_va, size)?;
            self.vmcoreinfo = Some(data);

            if let Some(vmci) = &self.vmcoreinfo {
                if let Ok(data) = String::from_utf8(vmci.to_vec()) {
                    for line in data.lines() {
                        info!("VMCOREINFO: {}", line);
                    }
                }
            }
        } else {
            return Err(Error::IoError("This is a problem. VMCOREINFO data isn't recoverable.".to_string()));
        }

        Ok(())
    }

    fn is_vmcoreinfo_present<P: ProgramHeader>(
        &self,
        endian: P::Endian,
        in_segments: &[P], 
        in_data: &[u8]) -> bool {

        let mut present = false;

        for section in in_segments.iter() {
            if let Ok(Some(mut notes)) = section.notes(endian, in_data) {
                while let Ok(Some(note)) = notes.next() {
                    if note.name() == b"VMCOREINFO" {

                        if let Ok(data) = String::from_utf8(note.desc().to_vec()) {
                            for line in data.lines() {
                                info!("VMCOREINFO: {}", line);
                            }
                        }

                        present = true;
                        break;
                    }
                }
            }
        }

        present
    }

    fn associate_mem_ranges<P: ProgramHeader<Word = u64>>(
        &mut self,
        endian: P::Endian,
        in_segments: &[P]
    ) -> Result<()> {
        let headers = in_segments
                        .iter()
                        .enumerate()
                        .filter(|(_, h)| h.p_type(endian) == PT_LOAD)
                        .filter(|(_, h)| h.p_paddr(endian) != u64::MAX)
                        .filter(|(_, h)| h.p_vaddr(endian) != 0)  
                        .map(|(_, h)| h);
        
        let mut out_file_off = 0;
        for h in headers {
            // This should always be true.
            assert_eq!(h.p_filesz(endian), h.p_memsz(endian));

            // NOTE: There is an issue on Amazon Linux and Ubuntu VMs where physaddr
            // is null when looking at "readelf -l /proc/kcore"
            // We retrieve the physical offset from /proc/iomem using the segment sizes.
            for mem_range in &self.iomem_ranges {
                println!("mem_range: {:#X?}", mem_range);
                if h.p_paddr(endian) == mem_range.start_phys_addr ||
                   (h.p_paddr(endian) == 0 && h.p_filesz(endian) == mem_range.memsz) ||
                   (h.p_paddr(endian) >= mem_range.start_phys_addr && h.p_paddr(endian) < mem_range.end_phys_addr) {

                    let delta = h.p_paddr(endian) - mem_range.start_phys_addr;
                    let is_virtual = delta > 0;

                    let start_phys_addr = mem_range.start_phys_addr + delta;
                    let memsz = h.p_filesz(endian);
                    assert_eq!(h.p_filesz(endian), h.p_memsz(endian));
                    if !is_virtual {
                        assert_eq!(memsz, mem_range.memsz);
                    }
                    let end_phys_addr = start_phys_addr + memsz;
                    let virt_addr = h.p_vaddr(endian);
                    let kcore_file_off = h.p_offset(endian);

                    self.mem_ranges.push(MemoryRange {
                        start_phys_addr,
                        end_phys_addr,
                        memsz,
                        virt_addr,
                        kcore_file_off,
                        out_file_off,
                        is_virtual,
                        p_flags: h.p_flags(endian)
                    });

                    if is_virtual == false {
                        out_file_off += memsz;
                    }

                    debug!("0x{:x}-0x{:x} va=0x{:x} kfo=0x{:x}",
                        start_phys_addr, end_phys_addr, virt_addr, kcore_file_off);
                }
            }
        }

        // Set the file_off variable in mem_ranges for the in_betweener.
        let mut virtual_file_off = 0;
        let mut virtual_id = None;
        for i in 0..self.mem_ranges.len() {
            if self.mem_ranges[i].is_virtual == false {
                continue;
            }
            virtual_id = Some(i);

            let orange = self.mem_ranges.iter()
                                        .enumerate()
                                        .filter(|(_, e)| self.mem_ranges[i].start_phys_addr >= e.start_phys_addr && self.mem_ranges[i].end_phys_addr < e.end_phys_addr)
                                        .map(|(_, e)| e)
                                        .next()
                                        .unwrap();

            let delta = self.mem_ranges[i].start_phys_addr - orange.start_phys_addr;
            virtual_file_off = self.mem_ranges[i].out_file_off + delta;
            assert!(delta > 0);
            break;
        }

        if let Some(virtual_id) = virtual_id {
            assert!(virtual_file_off > 0);
            self.mem_ranges[virtual_id].set_file_offset(virtual_file_off);
        }

        Ok(())
    }

    fn reserve_program_notes<P: ProgramHeader<Word = u64>>(
        &self,
        endian: P::Endian,
        writer: &mut object::write::elf::Writer,
        in_segments: &[P],
        in_data: &[u8]
    ) {
        let mut is_vmci_present = false;

        for section in in_segments.iter() {
            if let Ok(Some(mut notes)) = section.notes(endian, in_data) {
                while let Ok(Some(note)) = notes.next() {
                    // For some reasons writer.reserve() doesn't align things properly.
                    writer.reserve(mem::size_of::<NoteHeader64<Endianness>>(), ELF_ALIGN);
                    let pad = round_up(writer.reserved_len(), ELF_ALIGN) - writer.reserved_len();
                    writer.reserve(pad, 1);

                    writer.reserve(note.n_namesz(endian) as usize, 4);
                    let pad = round_up(writer.reserved_len(), ELF_ALIGN) - writer.reserved_len();
                    writer.reserve(pad, 1);

                    writer.reserve(note.n_descsz(endian) as usize, ELF_ALIGN);
                    let pad = round_up(writer.reserved_len(), ELF_ALIGN) - writer.reserved_len();
                    writer.reserve(pad, 1);
        
                    if note.name() == b"VMCOREINFO" {
                        is_vmci_present = true;
                        break;
                    }
                }
            }
        }

        if is_vmci_present == false {
            if let Some(data) = &self.vmcoreinfo {
                writer.reserve(mem::size_of::<NoteHeader64<Endianness>>(), ELF_ALIGN);
                let pad = round_up(writer.reserved_len(), ELF_ALIGN) - writer.reserved_len();
                writer.reserve(pad, 1);

                writer.reserve(b"VMCOREINFO\0".len(), ELF_ALIGN);
                let pad = round_up(writer.reserved_len(), ELF_ALIGN) - writer.reserved_len();
                writer.reserve(pad, 1);

                writer.reserve(data.len(), ELF_ALIGN);
                let pad = round_up(writer.reserved_len(), ELF_ALIGN) - writer.reserved_len();
                writer.reserve(pad, 1);
            }
        }
    }

    fn build_elf_header<P: ProgramHeader<Word = u64, Endian = Endianness>>(
        &self,
        endian: P::Endian,
        in_elf: &FileHeader64<Endianness>,
        in_segments: &[P], 
        in_data: &[u8],
        is_class_64: bool
    ) -> Result<Vec<u8>> {

        let mut out_data = Vec::new();
        let mut writer = object::write::elf::Writer::new(endian, is_class_64, &mut out_data);

        // reserve file header
        writer.reserve_file_header();
        assert!(in_elf.e_phoff(endian) == writer.reserved_len() as u64);
        // debug!("File header reserved. (size = 0x{:x})", writer.reserved_len());
        // reserve program headers (PT_NOTE + PT_LOAD)
        writer.reserve_program_headers((self.mem_ranges.len() + 1) as u32);
        // debug!("Program headers reserved. (size = 0x{:x})", writer.reserved_len());
        // reserve program notes
        let notes_off = writer.reserved_len() as u64;
        self.reserve_program_notes(endian, &mut writer, in_segments, in_data);
        let notes_sz = writer.reserved_len() as u64 - notes_off;
        // debug!("Program notes reserved. (size = 0x{:x})", writer.reserved_len());

        // null bytes
        let next_page_offset = round_up(writer.reserved_len(), PAGE_SIZE);
        writer.reserve_until(next_page_offset);
        debug!("Reserved size of the new ELF header is 0x{:x}.", writer.reserved_len());

        writer.write_file_header(&object::write::elf::FileHeader {
            os_abi: in_elf.e_ident().os_abi,
            abi_version: in_elf.e_ident().abi_version,
            e_type: in_elf.e_type(endian),
            e_machine: in_elf.e_machine(endian),
            e_entry: in_elf.e_entry(endian).into(),
            e_flags: in_elf.e_flags(endian),
        })?;
    
        writer.write_align_program_headers();

        // The first entry should be a PT_NOTE.
        debug!("write_program_header(PT_NOTE)...");
        writer.write_program_header(&object::write::elf::ProgramHeader {
            p_type  : PT_NOTE,
            p_flags : 0,
            p_offset: notes_off,
            p_vaddr : 0,
            p_paddr : 0,
            p_filesz: notes_sz,
            p_memsz : 0,
            // This needs to be zero for some tools.
            p_align : 0,
        });

        // The other entries are the PT_LOAD entries.
        // Building the new PHdrs
        // Blocks will be after the ELF Header.
        let file_header_size = writer.reserved_len() as u64;

        for mem_range in &self.mem_ranges {
            debug!("write_program_header(PT_LOAD)...");
            writer.write_program_header(&object::write::elf::ProgramHeader {
                p_type  : PT_LOAD,
                p_flags : mem_range.p_flags,
                p_offset: mem_range.out_file_off + file_header_size,
                p_vaddr : mem_range.virt_addr,
                p_paddr : mem_range.start_phys_addr,
                p_filesz: mem_range.memsz,
                p_memsz : mem_range.memsz,
                // This needs to be zero for some tools.
                p_align : 0,
            });
        }

        // Adding the Notes
        let mut is_vmci_present = false;

        for section in in_segments.iter() {
            if let Ok(Some(mut notes)) = section.notes(endian, in_data) {
                while let Ok(Some(note)) = notes.next() {
                    writer.write(object::bytes_of(&NoteHeader64 {
                        n_namesz: U32::new(endian, note.n_namesz(endian)),
                        n_descsz: U32::new(endian, note.n_descsz(endian)),
                        n_type: U32::new(endian, note.n_type(endian))
                    }));
                    writer.write_align(ELF_ALIGN);
                    writer.write(note.name());
                    // need padding, because note.name() doesn't keep the null terminator.
                    let null_bytes = note.n_namesz(endian) as usize - note.name().len();
                    for _i in 0..null_bytes {
                        writer.write(b"\0");
                    }
                    writer.write_align(ELF_ALIGN);
                    writer.write(note.desc());
                    writer.write_align(ELF_ALIGN);
        
                    if note.name() == b"VMCOREINFO" {
                        is_vmci_present = true;
                    }
                }
            }
        }

        if is_vmci_present == false {
            if let Some(data) = &self.vmcoreinfo {
                writer.write(object::bytes_of(&NoteHeader64 {
                        n_namesz: U32::new(endian, b"VMCOREINFO\0".len() as u32),
                        n_descsz: U32::new(endian, data.len() as u32),
                        n_type: U32::new(endian, 0x0), // VMCOREINFO type is 0x0
                }));
                writer.write_align(ELF_ALIGN);
                writer.write(b"VMCOREINFO\0");
                writer.write_align(ELF_ALIGN);
                writer.write(data);
                writer.write_align(ELF_ALIGN);
            }
        }

        writer.pad_until(writer.reserved_len());
        info!("Reconstructed ELF header length is 0x{:x}.", out_data.len());

        Ok(out_data)
    }

    fn parse_kcore(&mut self) -> Result<()> {
        let mut buffer = vec![0u8; 1 * 0x100000];
        self.kcore.read(&mut buffer)?;

        // Support for x64/ARM64 version of Linux only.
        let in_data = &*buffer;
        let in_elf = FileHeader64::<Endianness>::parse(in_data)?;
        let endian = in_elf.endian()?;
        let in_segments = in_elf.program_headers(endian, in_data)?;

        // Step 1: Parse /proc/kcore to look for any missing MemoryRange through the PHdrs.
        // We filter out the invalid PT_LOAD.
        self.associate_mem_ranges(endian, &in_segments)?;

        // Step 2.1 - Check if VMCOREINFO is present. This happens with old Linux OSes.
        let is_vmci_present = self.is_vmcoreinfo_present(endian, &in_segments, in_data);
        
        // Step 2.2 - VMCOREINFO is missing so we need to add it manually.
        if is_vmci_present == false {
            info!("VMCOREINFO is absent from /proc/kcore.");
            info!("Reading vmcoreinfo_data...");
            self.read_vmcoreinfo()?;
        } else {
            info!("VMCOREINFO is present in /proc/kcore.");
        }

        // Step 3 - We are building a new ELF file header.
        // This means, that we:
        //  - Add the VMCOREINFO PT_NOTE if it's not present.
        //  - Keep only the useful PT_LOAD headers, with the correct p_offset.
        let out_header = self.build_elf_header(endian,
                                               &in_elf,
                                               &in_segments,
                                               in_data,
                                               in_elf.is_class_64())?;
        self.out_header  = Some(out_header);

        Ok(())
    }

    #[allow(dead_code)]
    fn display(&self) {
        let table = Table::new(&self.mem_ranges)
            .with(Style::markdown());
        info!("Total number of memory ranges: {}", self.mem_ranges.len());
        println!("{}", table);
        
        if let Some(vmcoreinfo) = &self.vmcoreinfo {
            // let vec = buf[end..].to_vec();
            // String::from_utf8(vmcoreinfo)
            if let Ok(data) = String::from_utf8(vmcoreinfo.to_vec()) {
                for line in data.lines() {
                    info!("VMCOREINFO: {}", line);
                }
            }
        }
    }

    fn get_dump_size(&self) -> u64 {
        let mut file_size = self.out_header.as_ref().expect("ELF Header is not initialized").len() as u64;

        for range in &self.mem_ranges {
            if range.is_virtual {
                continue;
            }
            file_size += range.memsz;
        }

        file_size
    }

    fn write_kcore_dumpit(
        &self,
        dst: &mut dyn Write
    ) -> Result<()> {
        let out_data = self.out_header.as_ref().ok_or(
            Error::IoError("Object not initialized. Did you call init()?".to_string()))?;
        dst.write_all(&out_data[..])?;

        // Writing each of the memory range that is not virtual.
        let mut buf = vec![0u8; BLOCK_SIZE];
        let mut rdr = BufReader::new(&self.kcore);
            
        for range in &self.mem_ranges {
            let mut off = 0;
            if range.is_virtual {
                continue;
            }

            info!("Writing 0x{:x}-0x{:x} physical block...",
                    range.start_phys_addr, range.end_phys_addr);

            let bar = ProgressBar::new(range.memsz);
            rdr.seek(SeekFrom::Start(range.kcore_file_off))?;

            while off < range.memsz {
                let bytes_left = (range.memsz - off) as usize;
                let bytes_to_read = cmp::min(bytes_left, BLOCK_SIZE);

                rdr.read_exact(&mut buf[0..bytes_to_read])?;
                dst.write_all(&buf[0..bytes_to_read])?;

                off += bytes_to_read as u64;
                bar.inc(bytes_to_read as u64);
            }
        }

        Ok(())
    }

    fn write_to_archive(
        &self,
        dst: &mut dyn Write
    ) -> Result<()> {
        // Writing the archive.
        info!("Creating .tar.zst archive...");

        let now = Utc::now();
        let uts = uname()?;

        // The main memory dump.
        let file_name = format!("kcore.dumpit.{}.{}-{:02}-{:02}-{:02}{:02}.core",
            uts.release().to_str().unwrap_or("uname"),
            now.year(), now.month(), now.day(), now.hour(), now.minute());

        let mut encoder = zstd::stream::Encoder::new(dst, 3)?;
        {
            let mut tar = tar::Builder::new(&mut encoder);

            // TODO: Write additional useful files from /proc/
            info!("Writing /proc/kallsyms file...");
            let mut f = fs::File::open(format!("{}kallsyms", PROC_DIR))?;

            let mut data = String::new();
            f.read_to_string(&mut data)?;

            let mut hdr_syms = tar::Header::new_gnu();
            let hdr_syms_sz = data[..].as_bytes().len() as u64;
            hdr_syms.set_size(hdr_syms_sz); // Manually set the size because it's a link file.
            hdr_syms.set_path("proc/kallsyms")?;
            hdr_syms.set_mode(0o644);
            hdr_syms.set_uid(0);
            hdr_syms.set_gid(0);
            hdr_syms.set_mtime(0); 
            hdr_syms.set_cksum(); // Always call at the end.

            tar.append(&mut hdr_syms, data[..].as_bytes())?;

            info!("Writing {} file...", file_name);
            let mut header = tar::Header::new_gnu();
            let file_size = self.get_dump_size();
            header.set_size(file_size);
            header.set_path(&file_name)?;
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();

            tar.append(&mut header, std::io::empty())?;
            self.write_kcore_dumpit(tar.get_mut())?;

            tar.finish()?;
        }

        info!("Finished.");
        encoder.finish()?;

        Ok(())
    }

}

fn main() -> Result<()> {
    env_logger::Builder::new().filter_level(LevelFilter::max()).init();

    println!("DumpIt (For Linux - x64 & ARM64) {}", CRATE_VERSION);
    println!("Linux memory acquisition that makes sense.");
    println!("Copyright (c) 2022, Magnet Forensics, Inc.");
    println!("");

    let args = Args::parse();
    let mut out_file_path = args.output_path;
    let is_archive = !args.raw;

    if out_file_path.is_none() {
        // Generate the destination file name if no file is provided.
        let now = Utc::now();
        let uts = uname()?;

        // The main memory dump.
        let mut file_name = format!("dumpit.{}.{}-{:02}-{:02}-{:02}{:02}",
            uts.release().to_str().unwrap_or("uname"),
            now.year(), now.month(), now.day(), now.hour(), now.minute());

        if is_archive {
            file_name += ".tar.zst"
        } else {
            file_name += ".core";
        }

        out_file_path = Some(file_name);
        pause();
    }

    if let Some(ref o) = out_file_path {
        debug!("Destination file: {}", o);
    }

    let mut image = DumpItForLinux::new()?;
    image.init()?;
    // image.display();

    if let Some(ref file_path) = out_file_path {
        let start = Instant::now();

        let mut f = fs::File::create(&file_path.to_string())?;
        if is_archive == true {
            image.write_to_archive(&mut f)?;
        } else {
            image.write_kcore_dumpit(&mut f)?;
        }

        let duration = start.elapsed();
        info!("Total time elapsed: {:?}", duration);
    }

    Ok(())
}