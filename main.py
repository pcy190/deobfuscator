from analyzer import DeflatAnalyzer
from emulator import DeflatEmu

if __name__ == '__main__':
    filename = 'example/lib64_example.so'
    analyzer = DeflatAnalyzer(filename)
    analyzer.analysis_flatten_blocks(0x13C88)  # 0x13040 0x13C88
    analyzer.show_blocks_info()
    # add some special trampolines
    print("now running emu")
    emulator = DeflatEmu(analyzer, './rootfs/arm64_android')
    emulator.search_path(strategy=0)  # or strategy=1
    emulator.patch_code()


