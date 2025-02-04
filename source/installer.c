#include "installer.h"
#include "safewrite.h"
#include "validator.h"
#include "unittype.h"
#include "nand.h"
#include "sdmmc.h"
#include "ui.h"
#include "qff.h"
#include "hid.h"

#define COLOR_STATUS(s) ((s == STATUS_GREEN) ? COLOR_BRIGHTGREEN : (s == STATUS_YELLOW) ? COLOR_BRIGHTYELLOW : (s == STATUS_RED) ? COLOR_RED : COLOR_DARKGREY)

#define MIN_SD_FREE (16 * 1024 * 1024) // 16MB

#define NAME_SIGHAXFIRM     (IS_DEVKIT ? INPUT_PATH "/" NAME_FIRM "_dev.firm" : INPUT_PATH "/" NAME_FIRM ".firm")
#define NAME_SIGHAXFIRMSHA  (IS_DEVKIT ? INPUT_PATH "/" NAME_FIRM "_dev.firm.sha" : INPUT_PATH "/" NAME_FIRM ".firm.sha")
#define NAME_SECTOR0x96     (IS_DEVKIT ? INPUT_PATH "/secret_sector_dev.bin" : INPUT_PATH "/secret_sector.bin")
#define NAME_FIRMBACKUP     INPUT_PATH "/firm%lu_enc.bak"
#define NAME_SECTORBACKUP   INPUT_PATH "/sector0x96_enc.bak"

#define MAX_STAGE2_SIZE   0x89A00

#define STATUS_GREY    -1
#define STATUS_GREEN    0
#define STATUS_YELLOW   1
#define STATUS_RED      2

static int  statusA9lh         = STATUS_GREY;
static int  statusSdCard       = STATUS_GREY;
static int  statusFirm         = STATUS_GREY;
static int  statusSector       = STATUS_GREY;
static int  statusCrypto       = STATUS_GREY;
static int  statusBackup       = STATUS_GREY;
static int  statusInstall      = STATUS_GREY;
static char msgA9lh[64]        = "not started";
static char msgSdCard[64]      = "not started";
static char msgFirm[64]        = "not started";
static char msgSector[64]      = "not started";
static char msgCrypto[64]      = "not started";
static char msgBackup[64]      = "not started";
static char msgInstall[64]     = "not started";
    
u32 ShowInstallerStatus(void) {
    const u32 pos_xb = 10;
    const u32 pos_x0 = pos_xb + 4;
    const u32 pos_x1 = pos_x0 + (17*FONT_WIDTH_EXT);
    const u32 pos_yb = 10;
    const u32 pos_yu = 230;
    const u32 pos_y0 = pos_yb + 50;
    const u32 stp = 14;
    
    // DrawStringF(BOT_SCREEN, pos_xb, pos_yb, COLOR_STD_FONT, COLOR_STD_BG, "SafeB9SInstaller v" VERSION "\n" "-----------------------" "\n" "https://github.com/d0k3/SafeB9SInstaller");
    DrawStringF(BOT_SCREEN, pos_xb, pos_yb, COLOR_STD_FONT, COLOR_STD_BG, APP_TITLE "\n" "%.*s" "\n" APP_URL,
        strnlen(APP_TITLE, 32), "--------------------------------");
    
    DrawStringF(BOT_SCREEN, pos_x0, pos_y0 + (0*stp), COLOR_STD_FONT, COLOR_STD_BG, "ARM9LoaderHax  -");
    DrawStringF(BOT_SCREEN, pos_x0, pos_y0 + (1*stp), COLOR_STD_FONT, COLOR_STD_BG, "MicroSD Card   -");
    DrawStringF(BOT_SCREEN, pos_x0, pos_y0 + (2*stp), COLOR_STD_FONT, COLOR_STD_BG, "Sighaxed FIRM  -");
    DrawStringF(BOT_SCREEN, pos_x0, pos_y0 + (3*stp), COLOR_STD_FONT, COLOR_STD_BG, "Secret Sector  -");
    DrawStringF(BOT_SCREEN, pos_x0, pos_y0 + (4*stp), COLOR_STD_FONT, COLOR_STD_BG, "Crypto Status  -");
    DrawStringF(BOT_SCREEN, pos_x0, pos_y0 + (5*stp), COLOR_STD_FONT, COLOR_STD_BG, "Backup Status  -");
    DrawStringF(BOT_SCREEN, pos_x0, pos_y0 + (6*stp), COLOR_STD_FONT, COLOR_STD_BG, "Install Status -");
    
    DrawStringF(BOT_SCREEN, pos_x1, pos_y0 + (0*stp), COLOR_STATUS(statusA9lh)   , COLOR_STD_BG, "%-21.21s", msgA9lh   );
    DrawStringF(BOT_SCREEN, pos_x1, pos_y0 + (1*stp), COLOR_STATUS(statusSdCard) , COLOR_STD_BG, "%-21.21s", msgSdCard );
    DrawStringF(BOT_SCREEN, pos_x1, pos_y0 + (2*stp), COLOR_STATUS(statusFirm)   , COLOR_STD_BG, "%-21.21s", msgFirm   );
    DrawStringF(BOT_SCREEN, pos_x1, pos_y0 + (3*stp), COLOR_STATUS(statusSector) , COLOR_STD_BG, "%-21.21s", msgSector );
    DrawStringF(BOT_SCREEN, pos_x1, pos_y0 + (4*stp), COLOR_STATUS(statusCrypto) , COLOR_STD_BG, "%-21.21s", msgCrypto );
    DrawStringF(BOT_SCREEN, pos_x1, pos_y0 + (5*stp), COLOR_STATUS(statusBackup) , COLOR_STD_BG, "%-21.21s", msgBackup );
    DrawStringF(BOT_SCREEN, pos_x1, pos_y0 + (6*stp), COLOR_STATUS(statusInstall), COLOR_STD_BG, "%-21.21s", msgInstall);
    
    DrawStringF(BOT_SCREEN, pos_xb, pos_yu - 10, COLOR_STD_FONT, COLOR_STD_BG, APP_USAGE);
    return 0;
}

u32 SafeB9SInstaller(void) {
    UINT bt;
    u32 ret = 0;
    
    // initialization
    ShowString("Initializing, please wait...");
    
    
    // step #0 - a9lh check
    snprintf(msgA9lh, 64, (IS_A9LH && !IS_SIGHAX) ? "installed" : "not installed");
    statusA9lh = STATUS_GREEN;
    ShowInstallerStatus();
    
    // step #1 - init/check SD card
    snprintf(msgSdCard, 64, "checking...");
    statusSdCard = STATUS_YELLOW;
    ShowInstallerStatus();
    u64 sdFree = 0;
    u64 sdTotal = 0;
    if ((fs_init() != FR_OK) ||
        (f_getfreebyte("0:", &sdFree) != FR_OK) ||
        (f_gettotalbyte("0:", &sdTotal) != FR_OK)) {
        snprintf(msgSdCard, 64, "init failed");
        statusSdCard = STATUS_RED;
        return 1;
    }
    InitNandCrypto(true); // for sector0x96 crypto and NAND drives
    snprintf(msgSdCard, 64, "%lluMB/%lluMB free", sdFree / (1024 * 1024), sdTotal / (1024 * 1024));
    statusSdCard = (sdFree < MIN_SD_FREE) ? STATUS_RED : STATUS_GREEN;
    ShowInstallerStatus();
    if (sdFree < MIN_SD_FREE) return 1;
    // SD card okay!
    
    
    // step #2 - check sighaxed firm
    snprintf(msgFirm, 64, "checking...");
    statusFirm = STATUS_YELLOW;
    ShowInstallerStatus();
    u8 firm_sha[0x20];
    UINT firm_size;
    bool unknown_payload = false;
    if ((f_qread(NAME_SIGHAXFIRM, FIRM_BUFFER, 0, FIRM_BUFFER_SIZE, &firm_size) != FR_OK) ||
        (firm_size < 0x200)) {
        snprintf(msgFirm, 64, "file not found");
        statusFirm = STATUS_RED;
        return 1;
    }
    if ((f_qread(NAME_SIGHAXFIRMSHA, firm_sha, 0, 0x20, &bt) != FR_OK) || (bt != 0x20)) {
        snprintf(msgFirm, 64, ".sha file not found");
        statusFirm = STATUS_RED;
        return 1;
    }
    if (ValidateFirm(FIRM_BUFFER, firm_sha, firm_size, NULL) != 0) {
        snprintf(msgFirm, 64, "invalid FIRM");
        statusFirm = STATUS_RED;
        return 1;
    }
    if (CheckFirmSigHax(FIRM_BUFFER) != 0) {
        snprintf(msgFirm, 64, "not sighaxed");
        statusFirm = STATUS_RED;
        return 1;
    }
    if (CheckFirmPayload(FIRM_BUFFER, msgFirm) != 0) {
        #ifndef OPEN_INSTALLER
        statusFirm = STATUS_RED;
        return 1;
        #else
        unknown_payload = true;
        #endif
    }
    statusFirm = unknown_payload ? STATUS_YELLOW : STATUS_GREEN;
    ShowInstallerStatus();
    // provided FIRM is okay!
    
    
    // step #3 - check secret_sector.bin file
    u8 secret_sector[0x200] = { 0 };
    if (IS_A9LH && !IS_SIGHAX && !IS_O3DS) {
        snprintf(msgSector, 64, "checking...");
        statusSector = STATUS_YELLOW;
        ShowInstallerStatus();
        if ((f_qread(NAME_SECTOR0x96, secret_sector, 0, 0x200, &bt) != FR_OK) || (bt != 0x200)) {
            snprintf(msgSector, 64, "file not found");
            statusSector = STATUS_RED;
            return 1;
        }
        if (ValidateSector(secret_sector) != 0) {
            snprintf(msgSector, 64, "invalid file");
            statusSector = STATUS_RED;
            return 1;
        }
        snprintf(msgSector, 64, "loaded & verified");
    } else snprintf(msgSector, 64, "not required");
    statusSector = STATUS_GREEN;
    ShowInstallerStatus();
    // secret_sector.bin okay or not required!
    
    
    // step #4 - check NAND crypto
    snprintf(msgCrypto, 64, "checking...");
    statusCrypto = STATUS_YELLOW;
    ShowInstallerStatus();
    u32 n_firms = 0;
    for (; n_firms < 8; n_firms++) {
        NandPartitionInfo np_info;
        if (GetNandPartitionInfo(&np_info, NP_TYPE_FIRM, NP_SUBTYPE_CTR, n_firms) != 0) break;
        if ((firm_size > np_info.count * 0x200) || (np_info.count * 0x200 > WORK_BUFFER_SIZE)) {
            n_firms = 0;
            break;
        }
    }
    if (!n_firms) {
        snprintf(msgCrypto, 64, "FIRM partition fail");
        statusCrypto = STATUS_RED;
        return 1;
    }
    if (!CheckFirmCrypto()) {
        snprintf(msgCrypto, 64, "FIRM crypto fail");
        statusCrypto = STATUS_RED;
        return 1;
    }
    if ((IS_A9LH && !IS_SIGHAX && !IS_O3DS) && !CheckSector0x96Crypto()) {
        snprintf(msgCrypto, 64, "OTP crypto fail");
        statusCrypto = STATUS_RED;
        return 1;
    }
    snprintf(msgCrypto, 64, "all checks passed");
    statusCrypto = STATUS_GREEN;
    ShowInstallerStatus();
    
    
    // step #X - point of no return
    if (!ShowUnlockSequence(unknown_payload ? 6 : 1, unknown_payload ? 
        "!!! FIRM NOT RECOGNIZED !!!\nProceeding may lead to a BRICK!\n \nTo proceed, enter the sequence\nbelow or press B to cancel." :
        "All input files verified.\n \nTo install FIRM, enter the sequence\nbelow or press B to cancel.")) {
        snprintf(msgBackup, 64, "cancelled by user");
        snprintf(msgInstall, 64, "cancelled by user");
        statusBackup = STATUS_YELLOW;
        statusInstall = STATUS_YELLOW;
        return 1;
    }
    
    
    // step #5 - backup of current FIRMs and sector 0x96
    snprintf(msgBackup, 64, "FIRM backup...");
    statusBackup = STATUS_YELLOW;
    ShowInstallerStatus();
    ShowProgress(0, 0, "FIRM backup");
    for (u32 i = 0; i < n_firms; i++) {
        NandPartitionInfo np_info;
        ret = GetNandPartitionInfo(&np_info, NP_TYPE_FIRM, NP_SUBTYPE_CTR, i);
        if (ret != 0) break;
        u32 fsize = np_info.count * 0x200;
        u32 foffset = np_info.sector * 0x200;
        char bakname[64];
        snprintf(bakname, 64, NAME_FIRMBACKUP, i);
        snprintf(msgBackup, 64, "FIRM backup (%lu/%lu)", i, n_firms);
        ShowInstallerStatus();
        if ((ReadNandBytes(WORK_BUFFER, foffset, fsize, 0xFF) != 0) ||
            (SafeQWriteFile(bakname, WORK_BUFFER, fsize) != 0)) {
            ret = 1;
            break;
        }
        ShowProgress(i + 1, n_firms, "FIRM backup");
    }
    if (ret != 0) {
        snprintf(msgBackup, 64, "FIRM backup fail");
        statusBackup = STATUS_RED;
        return 1;
    }
    if ((IS_A9LH && !IS_SIGHAX)) {
        snprintf(msgBackup, 64, "0x96 backup...");
        ShowInstallerStatus();
        u8 sector_backup0[0x200];
        u8 sector_backup1[0x200];
        f_unlink(NAME_SECTORBACKUP);
        if ((ReadNandSectors(sector_backup0, 0x96, 1, 0xFF) != 0) ||
            (f_qwrite(NAME_SECTORBACKUP, sector_backup0, 0, 0x200, &bt) != FR_OK) || (bt != 0x200) ||
            (f_qread(NAME_SECTORBACKUP, sector_backup1, 0, 0x200, &bt) != FR_OK) || (bt != 0x200) ||
            (memcmp(sector_backup0, sector_backup1, 0x200) != 0)) {
            snprintf(msgBackup, 64, "0x96 backup fail");
            statusBackup = STATUS_RED;
            return 1;
        }
    }
    snprintf(msgBackup, 64, "backed up & verified");
    statusBackup = STATUS_GREEN;
    ShowInstallerStatus();
    // backups done
    
    
    // step #6 - install sighaxed FIRM
    snprintf(msgInstall, 64, "FIRM install...");
    statusInstall = STATUS_YELLOW;
    ShowInstallerStatus();
    #ifndef NO_WRITE
    ShowProgress(0, 0, "FIRM install");
    do {
        for (u32 i = 0; i < n_firms; i++) {
            NandPartitionInfo np_info;
            ret = GetNandPartitionInfo(&np_info, NP_TYPE_FIRM, NP_SUBTYPE_CTR, i);
            if (ret != 0) break;
            ret = SafeWriteNand(FIRM_BUFFER, np_info.sector * 0x200, firm_size, np_info.keyslot);
            if (ret != 0) break;
            ShowProgress(i+1, n_firms, "FIRM install");
            snprintf(msgInstall, 64, "FIRM install (%li/8)", i+1);
            ShowInstallerStatus();
        }
        if (ret != 0) break;
        uint8_t emptyStage2[MAX_STAGE2_SIZE]={0};
        // Uninstall a9lh stage 2 always if firm flashed ok
        // This prevents false positives in the event of cfw uninstall
        ret = sdmmc_nand_writesectors(0x5C000, MAX_STAGE2_SIZE / 0x200, emptyStage2);
        if (ret != 0) break;
        if ((IS_A9LH && !IS_SIGHAX)) {
            snprintf(msgInstall, 64, "0x96 revert...");
            ShowInstallerStatus();
            ret = SafeWriteNand(secret_sector, SECTOR_SECRET * 0x200, 0x200, IS_O3DS ? 0xFF : 0x11);
            if (ret == 0) snprintf(msgA9lh, 64, "uninstalled");
        }
    } while (false);
    if (ret == 0) {
        snprintf(msgInstall, 64, "install success!");
        statusInstall = STATUS_GREEN;
        return 0;
    } else {
        snprintf(msgInstall, 64, "install failed");
        statusInstall = STATUS_RED;
        if ((IS_A9LH && !IS_SIGHAX)) {
            snprintf(msgA9lh, 64, "fucked up");
            statusA9lh = STATUS_RED;
        }
        ShowInstallerStatus();
    }
    #elif !defined FAIL_TEST
    snprintf(msgInstall, 64, "no write mode");
    statusInstall = STATUS_YELLOW;
    return 0;
    #else
    snprintf(msgInstall, 64, "emergency mode");
    statusInstall = STATUS_YELLOW;
    ShowInstallerStatus();
    #endif
    
    
    // if we end up here: uhoh
    ShowPrompt(false, APP_TITLE " failed!\nThis really should not have happened :/.");
    ShowPrompt(false, "Your system is now reverted to\nit's earlier state.\n \nDO NOT TURN OFF YOUR 3DS NOW!");
    
    // try to revert to the earlier state
    snprintf(msgBackup, 64, "FIRM restore...");
    statusBackup = STATUS_YELLOW;
    ShowInstallerStatus();
    ShowProgress(0, 0, "FIRM restore");
    for (u32 i = 0; i < n_firms; i++) {
        NandPartitionInfo np_info;
        ret = GetNandPartitionInfo(&np_info, NP_TYPE_FIRM, NP_SUBTYPE_CTR, i);
        if (ret != 0) break;
        u32 fsize = np_info.count * 0x200;
        u32 foffset = np_info.sector * 0x200;
        char bakname[64];
        snprintf(bakname, 64, NAME_FIRMBACKUP, i);
        snprintf(msgBackup, 64, "FIRM restore (%lu/%lu)", i, n_firms);
        ShowInstallerStatus();
        if ((f_qread(bakname, WORK_BUFFER, 0, fsize, &bt) != FR_OK) || (bt != fsize) ||
            (WriteNandBytes(WORK_BUFFER, foffset, fsize, 0xFF) != 0)) {
            ret = 1;
            break;
        }
        ShowProgress(i + 1, n_firms, "FIRM restore");
    }
    if (ret != 0) {
        snprintf(msgBackup, 64, "FIRM restore fail");
        statusBackup = STATUS_RED;
        return 1;
    }
    if ((IS_A9LH && !IS_SIGHAX)) {
        snprintf(msgBackup, 64, "0x96 restore...");
        ShowInstallerStatus();
        u8 sector_backup[0x200];
        if ((f_qread(NAME_SECTORBACKUP, sector_backup, 0, 0x200, &bt) != FR_OK) || (bt != 0x200) ||
            (WriteNandSectors(sector_backup, SECTOR_SECRET, 1, 0xFF) != 0)) {
            snprintf(msgBackup, 64, "0x96 restore fail");
            statusBackup = STATUS_RED;
            return 1;
        }
        snprintf(msgA9lh, 64, "restored a9lh");
        statusA9lh = STATUS_YELLOW;
    }
    snprintf(msgBackup, 64, "backup restored");
    statusBackup = STATUS_YELLOW;
    snprintf(msgInstall, 64, "reverted system");
    statusInstall = STATUS_YELLOW;
    
    
    return 1;
}
