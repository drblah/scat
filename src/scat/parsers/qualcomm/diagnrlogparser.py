#!/usr/bin/env python3

from collections import namedtuple
from packaging import version
import binascii
import bitstring
import calendar
import logging
import struct

bitstring_ver = version.parse(bitstring.__version__)
if bitstring_ver >= version.parse('4.2.0'):
    bitstring.options.lsb0 = True
elif bitstring_ver >= version.parse('4.0.0'):
    bitstring.lsb0 = True
else:
    raise Exception("SCAT requires bitstring>=4.0.0")

import scat.parsers.qualcomm.diagcmd as diagcmd
import scat.util as util

class DiagNrLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.rrc_segments = dict()
        self.first_segment_item = None

        # Serving cell DL/UL NR-ARFCN and band from RRC SCell info; used to detect
        # TDD (TDD band, or DL == UL ARFCN) for the mac-nr-framed radioType field
        self.nr_scell_dl_arfcn = 0
        self.nr_scell_ul_arfcn = 0
        self.nr_scell_band = 0

        # Last C-RNTI seen in a RACH attempt (used as RNTI context for MAC CEs)
        self.nr_last_c_rnti = 0

        if self.parent:
            self.display_format = self.parent.display_format
        else:
            self.display_format = 'x'

        i = diagcmd.diag_log_get_lte_item_id
        c = diagcmd.diag_log_code_5gnr
        self.process = {
            # Management Layer 1
            i(c.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE): lambda x, y, z: self.parse_nr_ml1_meas_db_update(x, y, z),

            # MAC
            i(c.LOG_5GNR_L2_DL_DATA_PDU): lambda x, y, z: self.parse_nr_l2_dl_data_pdu(x, y, z),
            i(c.LOG_5GNR_L2_UL_DATA_PDU): lambda x, y, z: self.parse_nr_l2_ul_data_pdu(x, y, z),
            i(c.LOG_5GNR_L2_UL_TB): lambda x, y, z: self.parse_nr_l2_ul_tb(x, y, z),
            i(c.LOG_5GNR_L2_UL_BSR): lambda x, y, z: self.parse_nr_l2_ul_bsr(x, y, z),
            i(c.LOG_5GNR_MAC_UL_TB_STATS): lambda x, y, z: self.parse_nr_mac_ul_tb_stats(x, y, z),
            i(c.LOG_5GNR_MAC_UL_PHYS_CHAN_SCHED): lambda x, y, z: self.parse_nr_mac_ul_phys_chan_sched(x, y, z),
            i(c.LOG_5GNR_MAC_DCI_INFO): lambda x, y, z: self.parse_nr_mac_dci_info(x, y, z),
            i(c.LOG_5GNR_MAC_DL_TB_REPORT): lambda x, y, z: self.parse_nr_mac_dl_tb_report(x, y, z),
            i(c.LOG_5GNR_MAC_RACH_TRIGGER): lambda x, y, z: self.parse_nr_mac_rach_trigger(x, y, z),
            i(c.LOG_5GNR_MAC_RACH_ATTEMPT): lambda x, y, z: self.parse_nr_mac_rach_attempt(x, y, z),

            # RRC
            i(c.LOG_5GNR_RRC_OTA_MESSAGE): lambda x, y, z: self.parse_nr_rrc(x, y, z),
            i(c.LOG_5GNR_RRC_MIB_INFO): lambda x, y, z: self.parse_nr_mib_info(x, y, z),
            i(c.LOG_5GNR_RRC_SERVING_CELL_INFO): lambda x, y, z: self.parse_nr_rrc_scell_info(x, y, z),
            # i(c.LOG_5GNR_RRC_CONFIGURATION_INFO): lambda x, y, z: self.parse_nr_rrc_conf_info(x, y, z),
            i(c.LOG_5GNR_RRC_SUPPORTED_CA_COMBOS): lambda x, y, z: self.parse_nr_cacombos(x, y, z),

            # NAS
            i(c.LOG_5GNR_NAS_5GSM_PLAIN_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB800),
            i(c.LOG_5GNR_NAS_5GSM_PLAIN_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB801),
            i(c.LOG_5GNR_NAS_5GSM_SEC_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB808),
            i(c.LOG_5GNR_NAS_5GSM_SEC_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB809),
            i(c.LOG_5GNR_NAS_5GMM_PLAIN_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB80A),
            i(c.LOG_5GNR_NAS_5GMM_PLAIN_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB80B),
            i(c.LOG_5GNR_NAS_5GMM_PLAIN_OTA_CONTAINER_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB814),
            i(c.LOG_5GNR_NAS_5GMM_STATE): lambda x, y, z: self.parse_nr_mm_state(x, y, z),
        }

        self.nr_pkt_ver = namedtuple('QcDiagNrPktVer', 'rel_min rel_maj')

    def update_parameters(self, display_format: str, gsmtapv3: bool):
        self.display_format = display_format

    def parse_float_q7(self, data_to_convert: int) -> float:
        if data_to_convert == 0:
            return 0
        integer = (data_to_convert >> 7) & 0xff
        frac = data_to_convert & 0x7f
        sig = (((integer^0xff)+1)* (-1)) + frac * 0.0078125
        return sig

    # ML1
    def parse_nr_ml1_meas_db_update(self, pkt_header, pkt_body: bytes, args: dict):
        stdout = ''
        pkt_ver = self.nr_pkt_ver._make(struct.unpack('<HH', pkt_body[0:4]))
        num_layers = 0
        current_offset = 0
        ml1_shared_struct_v2_7 = namedtuple('QcDiagNrMl1PacketV2_7', 'num_layers ssb_periocity null frequency_offset timing_offset')
        ml1_shared_struct_v2_9 = namedtuple('QcDiagNrMl1PacketV2_9', 'unknown num_layers ssb_periocity null frequency_offset timing_offset')

        if pkt_ver.rel_maj == 0x02:
            if pkt_ver.rel_min == 0x07:
                ml1_2_7 = ml1_shared_struct_v2_7._make(struct.unpack('<BB2sII', pkt_body[4:16]))
                num_layers = ml1_2_7.num_layers
                stdout += "NR ML1 Meas Packet: Layers: {}, ssb_periocity: {}\n".format(ml1_2_7.num_layers, ml1_2_7.ssb_periocity)
                current_offset = 16
            elif pkt_ver.rel_min in (0x09, 0x0a):
                ml1_2_9 = ml1_shared_struct_v2_9._make(struct.unpack('<IBBHII', pkt_body[4:20]))
                num_layers = ml1_2_9.num_layers
                stdout += "NR ML1 Meas Packet: Layers: {}, ssb_periocity: {}\n".format(ml1_2_9.num_layers, ml1_2_9.ssb_periocity)
                current_offset = 20
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Unknown NR ML1 Information packet, version: {}.{}'.format(pkt_ver.rel_maj, pkt_ver.rel_min))
                    self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
                return
        elif pkt_ver.rel_maj == 0x03:
            if pkt_ver.rel_min == 0x00:
                ml1_3_0 = ml1_shared_struct_v2_9._make(struct.unpack('<IBBHII', pkt_body[4:20]))
                num_layers = ml1_3_0.num_layers
                stdout += "NR ML1 Meas Packet: Layers: {}, ssb_periocity: {}\n".format(ml1_3_0.num_layers, ml1_3_0.ssb_periocity)
                current_offset = 20
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Unknown NR ML1 Information packet, version: {}.{}'.format(pkt_ver.rel_maj, pkt_ver.rel_min))
                    self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
                return
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR ML1 Information packet, version: {}.{}'.format(pkt_ver.rel_maj, pkt_ver.rel_min))
                self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return

        meas_carrier_list_struct = namedtuple('QcDiagNrMl1Packet', 'raster_arfcn num_cells serv_cell_index serv_cell_pci serv_ssb null_0 serv_rsrp_rx_0 serv_rsrp_rx_1 serv_rx_beam_0 serv_rx_beam_1 serv_rfic_id null_1 serv_subarr_0 serv_subarr_1')
        meas_carrier_list_struct_v3 = namedtuple('QcDiagNrMl1PacketV3', 'raster_arfcn cc_id num_cells serv_cell_pci serv_cell_index serv_ssb null_0 serv_rsrp_rx_0 serv_rsrp_rx_1 serv_rsrp_rx_2 serv_rsrp_rx_3 serv_rx_beam_0 serv_rx_beam_1 serv_rfic_id null_1 serv_subarr_0 serv_subarr_1')

        for layer in range(num_layers):
            if pkt_ver.rel_maj == 0x02:
                if pkt_ver.rel_min in (0x07, 0x09, 0x0a):
                    meas_carrier_list = meas_carrier_list_struct._make(struct.unpack('<IBBHB3sIIHHH2sHH', pkt_body[current_offset:current_offset+32]))
                    current_offset += 32
            elif pkt_ver.rel_maj == 0x03:
                if pkt_ver.rel_min in (0x00, ):
                    meas_carrier_list = meas_carrier_list_struct_v3._make(struct.unpack('<IBBHBB2sIIIIHHH2sHH', pkt_body[current_offset:current_offset+40]))
                    current_offset += 40

            if pkt_ver.rel_maj == 0x02:
                rsrp_str = 'RSRP: {:.2f}/{:.2f}'.format(
                    self.parse_float_q7(meas_carrier_list.serv_rsrp_rx_0), self.parse_float_q7(meas_carrier_list.serv_rsrp_rx_1),
                )
            elif pkt_ver.rel_maj == 0x03:
                if isinstance(meas_carrier_list, meas_carrier_list_struct_v3):
                    rsrp_str = 'RSRP: {:.2f}/{:.2f}/{:.2f}/{:.2f}'.format(
                        self.parse_float_q7(meas_carrier_list.serv_rsrp_rx_0), self.parse_float_q7(meas_carrier_list.serv_rsrp_rx_1),
                        self.parse_float_q7(meas_carrier_list.serv_rsrp_rx_2), self.parse_float_q7(meas_carrier_list.serv_rsrp_rx_3),
                    )
                else:
                    rsrp_str = ''
            stdout += "Layer {}: NR-ARFCN: {}, SCell PCI: {:4d}/SSB: {}, {}, RX beam: {}/{}, Num Cells: {} (S: {})\n".format(
                layer, meas_carrier_list.raster_arfcn, meas_carrier_list.serv_cell_pci, meas_carrier_list.serv_ssb & 0xf,
                rsrp_str,
                meas_carrier_list.serv_rx_beam_0 if meas_carrier_list.serv_rx_beam_0 != 0xffff else 'NA',
                meas_carrier_list.serv_rx_beam_1 if meas_carrier_list.serv_rx_beam_1 != 0xffff else 'NA',
                meas_carrier_list.num_cells, meas_carrier_list.serv_cell_index)
            # The ML1 measurement DB streams long before the RRC SCell Info
            # (0xB823) shows up; remember the serving raster ARFCN so that
            # MAC-NR emissions can already tell TDD from FDD. SCell info
            # (which also knows the UL ARFCN and band) stays authoritative.
            if not self.nr_scell_dl_arfcn and meas_carrier_list.raster_arfcn:
                self.nr_scell_dl_arfcn = meas_carrier_list.raster_arfcn

            if meas_carrier_list.num_cells == 0xff or meas_carrier_list.num_cells == 0x00:
                if meas_carrier_list.serv_cell_index > 0x00 and meas_carrier_list.serv_cell_index < 0xff:
                    num_cells = meas_carrier_list.serv_cell_index
                else:
                    num_cells = 0
            else:
                num_cells = meas_carrier_list.num_cells

            for cell in range(num_cells):
                cell_list_struct = namedtuple('QcDiagNrMl1Packet', 'pci pbch_sfn num_beams null_0 cell_quality_rsrp cell_quality_rsrq')
                cell_list = cell_list_struct._make(struct.unpack('<HHB3sII', pkt_body[current_offset:current_offset+16]))
                current_offset += 16
                stdout += "└── Cell {}: PCI: {:4d}, PBCH SFN: {}, RSRP: {:.2f}, RSRQ: {:.2f}, Num Beams: {}\n".format(
                    cell, cell_list.pci, cell_list.pbch_sfn,
                    self.parse_float_q7(cell_list.cell_quality_rsrp), self.parse_float_q7(cell_list.cell_quality_rsrq),
                    cell_list.num_beams)
                for beam in range(cell_list.num_beams):
                    beam_meas_struct = namedtuple('QcDiagNrMl1Packet', 'ssb_index null_0 rx_beam_0 rx_beam_1 null_1 ssb_ref_timing rx_beam_info_rsrp_0 rx_beam_info_rsrp_1 nr2nr_filtered_beam_rsrp_l3 nr2nr_filtered_beam_rsrq_l3 l_2_nr_filtered_tx_beam_rsrp_l3 l_2_nr_filtered_tx_beam_rsrq_l3')
                    beam_meas_struct_v3 = namedtuple('QcDiagNrMl1PacketV3', 'ssb_index null_0 rx_beam_0 rx_beam_1 null_1 ssb_ref_timing rx_beam_info_rsrp_0 rx_beam_info_rsrp_1 unk_0 unk_1 unk_2 unk_3 unk_4 unk_5 unk_6 unk_7 unk_8 unk_9 nr2nr_filtered_beam_rsrp_l3 nr2nr_filtered_beam_rsrq_l3 l_2_nr_filtered_tx_beam_rsrp_l3 l_2_nr_filtered_tx_beam_rsrq_l3')
                    if pkt_ver.rel_maj == 0x02 and pkt_ver.rel_min in (0x07, 0x09):
                        beam_meas_data = pkt_body[current_offset: current_offset+44]
                        if len(beam_meas_data) < 44:
                            current_offset += len(beam_meas_data)
                            continue
                        beam_meas = beam_meas_struct._make(struct.unpack('<HHHHIQIIIIII', beam_meas_data))
                        current_offset += len(beam_meas_data)
                        stdout += "    └── Beam {}: SSB[{}] Beam ID: {}/{}, RSRP: {:.2f}/{:.2f}, Filtered RSRP/RSRQ (Nr2Nr): {:.2f}/{:.2f}, Filtered RSRP/RSRQ (L2Nr): {:.2f}/{:.2f}\n".format(
                            beam, beam_meas.ssb_index,
                            beam_meas.rx_beam_0, beam_meas.rx_beam_1,
                            self.parse_float_q7(beam_meas.rx_beam_info_rsrp_0), self.parse_float_q7(beam_meas.rx_beam_info_rsrp_1),
                            self.parse_float_q7(beam_meas.nr2nr_filtered_beam_rsrp_l3), self.parse_float_q7(beam_meas.nr2nr_filtered_beam_rsrq_l3),
                            self.parse_float_q7(beam_meas.l_2_nr_filtered_tx_beam_rsrp_l3), self.parse_float_q7(beam_meas.l_2_nr_filtered_tx_beam_rsrq_l3),
                        )
                    elif (pkt_ver.rel_maj == 0x02 and pkt_ver.rel_min in (0x0a, )) or pkt_ver.rel_maj == 0x03:
                        beam_meas_data = pkt_body[current_offset: current_offset+84]
                        if len(beam_meas_data) < 84:
                            current_offset += len(beam_meas_data)
                            continue
                        beam_meas = beam_meas_struct_v3._make(struct.unpack('<HHHHIQIIIIIIIIIIIIIIII', beam_meas_data))
                        current_offset += len(beam_meas_data)
                        stdout += "    └── Beam {}: SSB[{}] Beam ID: {}/{}, RSRP: {:.2f}/{:.2f}, RSRQ: {:.2f}/{:.2f}, Filtered RSRP/RSRQ (Nr2Nr): {:.2f}/{:.2f}, Filtered RSRP/RSRQ (L2Nr): {:.2f}/{:.2f}\n".format(
                            beam, beam_meas.ssb_index,
                            beam_meas.rx_beam_0, beam_meas.rx_beam_1,
                            self.parse_float_q7(beam_meas.rx_beam_info_rsrp_0), self.parse_float_q7(beam_meas.rx_beam_info_rsrp_1),
                            self.parse_float_q7(beam_meas.unk_0), self.parse_float_q7(beam_meas.unk_1),
                            self.parse_float_q7(beam_meas.nr2nr_filtered_beam_rsrp_l3), self.parse_float_q7(beam_meas.nr2nr_filtered_beam_rsrq_l3),
                            self.parse_float_q7(beam_meas.l_2_nr_filtered_tx_beam_rsrp_l3), self.parse_float_q7(beam_meas.l_2_nr_filtered_tx_beam_rsrq_l3),
                        )

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        return {'stdout': stdout.rstrip(), 'ts': pkt_ts}

    # MAC

    # FR1 bands that use TDD duplexing (TS 38.101-1 Table 5.2-1). All FR2 bands
    # (number >= 257) are TDD as well. Used to pick the mac-nr-framed radioType.
    nr_tdd_bands = frozenset((34, 38, 39, 40, 41, 46, 47, 48, 50, 51, 53, 77, 78, 79, 96, 104))
    # DL frequency ranges (MHz) of FR1 TDD bands, as a fallback for when the
    # serving-cell band number is not (yet) known but the DL NR-ARFCN is.
    # Ambiguities with FDD bands are noted per line; the frequency fallback is
    # only used during the window before 0xB823 provides the band.
    nr_tdd_band_freq_ranges_mhz = (
        (1880, 1920),    # n39 (n3 DL reaches 1880: 1880.0 itself is ambiguous)
        (2010, 2025),    # n34
        (2300, 2400),    # n40 (n30 FDD DL 2350-2360 lies inside: assumed TDD, n30 NR is rare)
        (2496, 2690),    # n41 (n7 FDD DL 2620-2690 overlaps: assumed TDD, n7 NR is rare)
        (3300, 4200),    # n77/n78 (no FR1 FDD band is in this range)
        (3550, 3700),    # n48 (inside n77 range, listed for clarity)
        (4400, 5000),    # n79
        (5150, 5925),    # n46/n47 (no FR1 FDD band is in this range)
        (5925, 7125),    # n96/n104 (unlicensed, no FDD competition)
    )

    def nr_is_tdd(self) -> bool:
        """Whether the NR serving cell uses TDD duplexing, for mac-nr-framed radioType.
        Based on the serving-cell band (0xB823), the DL==UL ARFCN heuristic, and,
        when the band is unknown, the DL NR-ARFCN position within FR1/FR2 TDD
        frequency ranges. Note that TS 38.101-1 Table 5.2-1 lists more TDD bands
        than the frequency fallback can distinguish."""
        if self.nr_scell_band in self.nr_tdd_bands or self.nr_scell_band >= 257:
            return True
        if self.nr_scell_dl_arfcn and self.nr_scell_dl_arfcn == self.nr_scell_ul_arfcn:
            return True
        if self.nr_scell_dl_arfcn:
            # All FR2 (ARFCN > 2016666, i.e. above 24250 MHz) is TDD
            if self.nr_scell_dl_arfcn > 2016666:
                return True
            if not self.nr_scell_band:
                # NR-ARFCN to frequency per TS 38.101-1 Table 5.4.2.3-1, which
                # has two FR1 segments: below 3000 MHz FREF = 15 kHz * NREF;
                # at and above 3000 MHz FREF = 3000 MHz + 15 kHz * (NREF-600000)
                arfcn = self.nr_scell_dl_arfcn
                if arfcn < 600000:
                    freq_mhz = arfcn * 0.015
                else:
                    freq_mhz = 3000.0 + 0.015 * (arfcn - 600000)
                for low, high in self.nr_tdd_band_freq_ranges_mhz:
                    if low <= freq_mhz <= high:
                        return True
        return False

    # NR MAC RACH Attempt (0xB88A) per-version field offsets.
    # v0x07/v0x0A/v0x0E are the field-grounded layouts from lukejenkins/diaggrok
    # (diag_0xb88a.py; 276 records over SDX55/SDX62/SDX72). v0x05 (118 B,
    # SDXLEMUR "olympic", e.g. SIMCOM SIM8262) was derived from live captures;
    # body length varies (118/120/124 B seen) due to padding. Fixed offsets:
    # msg1 timing @24, preamble @34, msg2 @44, msg3 @48, post_rnti @112 (first
    # of the trailing (u16 RNTI, 0x01, 0x01) records); c_rnti is found by
    # matching a record against post_rnti (the fixed @84 shifts to @85 on
    # longer bodies). The fields at @38 ("ra_rnti"), @40/42 ("RAR window"),
    # @46 ("tc_rnti") and @60 ("msg4") could NOT be grounded against any vendor
    # reference: on live captures they hold the same values on every attempt
    # (0x001b/0x010b-0x0036/0x0100/"9b 0b"-style words) even when msg1 timings,
    # preambles and SFNs differ, and the decoded "Msg4" timing always precedes
    # Msg3 -- impossible per 38.321 5.15. diaggrok documents the timing fields
    # as u16+u16 pairs with the high word in {0x0000, 0x0001, 0x0101}; these
    # look like misaligned readings of such pairs. They are printed as
    # unverified raw words instead of being mislabeled. The field at ~@88 is
    # NOT the UL-CCCH SDU -- the real Msg3 SDU (from 0xB821) never appears in
    # this packet, so v0x05 emits only the C-RNTI CE.
    nr_mac_rach_attempt_layout = {
        0x05: dict(size=118, counter=8, ctype=None, mask=None, msg1=24, preamble=34,
                   pathloss=36, ra_rnti=38, win_start=40, win_end=42,
                   msg2=44, tc_rnti=46, ta=None, rapid=None,
                   msg3=48, msg4=60, grant=None, c_rnti=84, ccch=88, post_rnti=112),
        0x07: dict(size=108, counter=16, ctype=22, mask=23, msg1=28, preamble=35,
                   root=38, cv=40, ncs=None, ra_rnti=42, win_start=44, win_end=48,
                   msg2=56, tc_rnti=62, ta=64, rapid=None,
                   msg3=68, msg4=None, grant=72, c_rnti=None, ccch=80, post_rnti=104),
        0x0A: dict(size=180, counter=8, ctype=18, mask=19, msg1=68, preamble=78,
                   root=76, cv=80, ncs=82, ra_rnti=84, win_start=92, win_end=96,
                   msg2=112, tc_rnti=118, ta=120, rapid=132,
                   msg3=136, msg4=None, grant=140, c_rnti=148, ccch=152, post_rnti=176),
        0x0E: dict(size=196, counter=8, ctype=18, mask=19, msg1=84, preamble=94,
                   root=92, cv=96, ncs=98, ra_rnti=100, win_start=108, win_end=112,
                   msg2=128, tc_rnti=138, ta=140, rapid=152,
                   msg3=156, msg4=None, grant=132, c_rnti=166, ccch=168, post_rnti=192),
    }

    @staticmethod
    def nr_mac_timing_word(data: bytes, off: int) -> tuple:
        """(sfn, slot) from a packed u16 timing word; (None, None) when empty.
        Slot is 6 bits, so slots 0-63 decode correctly up to mu=3 (FR1, 40
        slots/frame at 120 kHz); at mu=4 (FR2, 80 slots/frame) slot numbers
        >= 64 would truncate."""
        if off is None or off + 2 > len(data):
            return None, None
        w = struct.unpack('<H', data[off:off+2])[0]
        if w == 0:
            return None, None
        return w & 0x3ff, (w >> 10) & 0x3f

    def parse_nr_mac_rach_attempt(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        if len(pkt_body) < 1:
            return None
        version = pkt_body[0]
        layout = self.nr_mac_rach_attempt_layout.get(version)
        if self.parent:
            self.parent.logger.log(logging.DEBUG, 'NR MAC RACH Attempt raw: {}'.format(util.xxd_oneline(pkt_body)))
        if layout is None or len(pkt_body) < layout['size']:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR MAC RACH Attempt packet version 0x{:02x}'.format(version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return {'stdout': 'NR MAC RACH Attempt (v0x{:02x}): {}'.format(version, util.xxd_oneline(pkt_body)), 'ts': pkt_ts}

        u16 = lambda off: struct.unpack('<H', pkt_body[off:off+2])[0] if off is not None and off + 2 <= len(pkt_body) else 0
        u8 = lambda off: pkt_body[off] if off is not None and off < len(pkt_body) else 0

        msg1_sfn, msg1_slot = self.nr_mac_timing_word(pkt_body, layout['msg1'])
        msg2_sfn, msg2_slot = self.nr_mac_timing_word(pkt_body, layout['msg2'])
        msg3_sfn, msg3_slot = self.nr_mac_timing_word(pkt_body, layout['msg3'])
        msg4_sfn, msg4_slot = self.nr_mac_timing_word(pkt_body, layout['msg4'])
        ws_sfn, ws_slot = self.nr_mac_timing_word(pkt_body, layout['win_start'])
        we_sfn, we_slot = self.nr_mac_timing_word(pkt_body, layout['win_end'])

        preamble = u8(layout['preamble']) if version == 0x07 or version == 0x05 else u16(layout['preamble'])
        ra_rnti = u16(layout['ra_rnti'])
        tc_rnti = u16(layout['tc_rnti']) if layout.get('tc_rnti') is not None else None
        if tc_rnti == 0xffff:
            tc_rnti = None  # vendor "none" sentinel (cf. diaggrok diag_0xb88a.py)
        c_rnti = u16(layout['c_rnti']) if layout.get('c_rnti') is not None else None
        if c_rnti == 0xffff:
            c_rnti = None
        post_rnti = u16(layout['post_rnti'])
        if version == 0x05 and len(pkt_body) >= 114 and post_rnti:
            # v0x05 has variable padding, so the fixed c_rnti offset shifts with
            # the packet length (seen 84/85 for 118/124-byte bodies). The tail is
            # a list of (u16 RNTI, 0x01, 0x01) records with post-RNTI first at
            # offset 112; the C-RNTI record is the one matching post-RNTI before it.
            for p in range(80, 112):
                if pkt_body[p+2:p+4] == b'\x01\x01' and struct.unpack('<H', pkt_body[p:p+2])[0] == post_rnti:
                    c_rnti = post_rnti
                    break
        if c_rnti:
            self.nr_last_c_rnti = c_rnti
        mask = u8(layout['mask']) if layout.get('mask') is not None else None

        stdout = 'NR MAC RACH Attempt v0x{:02x}: preamble={}, Msg1 SFN={} slot={}'.format(
            version, preamble, msg1_sfn, msg1_slot)
        if version == 0x05:
            # v0x05: offsets @38/@40/@42/@46/@60 are NOT grounded (see layout
            # comment) -- print the raw words as unverified instead of guessing
            # an interpretation.
            stdout += (', unverified: w38=0x{:04x} w40=0x{:04x} w42=0x{:04x} '
                       'w46=0x{:04x} w60=0x{:04x}').format(
                u16(layout['ra_rnti']), u16(layout['win_start']), u16(layout['win_end']),
                u16(layout['tc_rnti']), u16(layout['msg4']))
        else:
            ra_rnti = u16(layout['ra_rnti'])
            rnti_note = ' RA-RNTI={}'.format(ra_rnti) if ra_rnti else ''
            if rnti_note:
                # insert after 'preamble=..., ' -- keep the classic ordering
                stdout = ('NR MAC RACH Attempt v0x{:02x}: preamble={},{} Msg1 SFN={} slot={}'
                          ).format(version, preamble, rnti_note, msg1_sfn, msg1_slot)
            if ws_sfn is not None:
                stdout += ', RAR window {}/{} - {}/{}'.format(ws_sfn, ws_slot, we_sfn, we_slot)
        if msg2_sfn is not None:
            stdout += ', Msg2 SFN={} slot={}'.format(msg2_sfn, msg2_slot)
            if version != 0x05 and tc_rnti:
                stdout += ' TC-RNTI=0x{:04x}'.format(tc_rnti)
            if layout.get('ta') is not None and u16(layout['ta']):
                stdout += ' TA={}'.format(u16(layout['ta']))
            if layout.get('rapid') is not None and u16(layout['rapid']):
                stdout += ' RAPID={}'.format(u16(layout['rapid']))
        if msg3_sfn is not None:
            stdout += ', Msg3 SFN={} slot={}'.format(msg3_sfn, msg3_slot)
            if c_rnti:
                stdout += ' C-RNTI=0x{:04x}'.format(c_rnti)
        if msg4_sfn is not None and version != 0x05:
            stdout += ', Msg4 SFN={} slot={}'.format(msg4_sfn, msg4_slot)
        if post_rnti:
            stdout += ', post-RACH RNTI=0x{:04x}'.format(post_rnti)
        if mask is not None:
            stdout += ', msg_bitmask=0x{:02x}'.format(mask)

        result = {'stdout': stdout, 'ts': pkt_ts}

        # Emit a MAC-NR UL packet for the RACH Msg3 when the attempt reached Msg3.
        # For v0x07/v0x0A/v0x0E the ccch field holds the raw 48-bit UL-CCCH SDU
        # without a MAC subheader (cf. diaggrok diag_0xb88a.py: "msg3_ccch_sdu is
        # the UL-CCCH PDU, byte for byte"), so wrap it in a UL-SCH subheader with
        # LCID 52 ("CCCH (48 bits)", E=0). On v0x05 that field does NOT contain the
        # SDU (verified against the 0xB821 RRC OTA log: the real Setup Request
        # never appears in 0xB88A), so only the C-RNTI MAC CE is emitted there:
        # subheader LCID 58 + 2-byte CE. The Msg3 RRC content itself is available
        # from the 0xB821 log via '-L rrc'.
        ccch_off = layout.get('ccch') if version != 0x05 else None
        if ccch_off is not None and ccch_off + 6 <= len(pkt_body):
            ccch_sdu = pkt_body[ccch_off:ccch_off+6]
            if ccch_sdu != b'\x00' * 6:
                body = bytes([0x34]) + ccch_sdu
                desc = 'Msg3 UL-CCCH SDU: {}'.format(ccch_sdu.hex())
            elif c_rnti:
                body = bytes([0x3a]) + struct.pack('>H', c_rnti)
                desc = 'Msg3 C-RNTI CE: 0x{:04x}'.format(c_rnti)
            else:
                body = None
        elif c_rnti:
            body = bytes([0x3a]) + struct.pack('>H', c_rnti)
            desc = 'Msg3 C-RNTI CE: 0x{:04x}'.format(c_rnti)
        else:
            body = None
        if body is not None:
            # Msg3's PUSCH is scheduled with the TC-RNTI once the RAR was received
            # (38.321 5.15/4.5b), so prefer the TC-RNTI over the RA-RNTI when the
            # attempt has no C-RNTI yet. Wireshark's mac-nr-framed has no TC-RNTI
            # type, so the closest type (C-RNTI, which the TC-RNTI becomes after
            # contention resolution) is used in that case.
            rnti = c_rnti if c_rnti else (tc_rnti if tc_rnti else ra_rnti)
            rnti_type = util.mac_nr_rnti_types.C_RNTI if (c_rnti or tc_rnti) else util.mac_nr_rnti_types.RA_RNTI
            sfn, slot = (msg3_sfn, msg3_slot) if msg3_sfn is not None else (msg1_sfn, msg1_slot)
            # TDD for TDD bands (n78 etc.), for FR2, or when DL/UL NR-ARFCN coincide
            radio_type = util.mac_nr_radio_types.TDD_RADIO if self.nr_is_tdd() else util.mac_nr_radio_types.FDD_RADIO
            mac_pkt = util.create_nr_mac_gsmtap_packet(
                pkt_ts, is_downlink=False, rnti_type=rnti_type, body=body,
                rnti=rnti, sfn=sfn, slot=slot, arfcn=self.nr_scell_dl_arfcn,
                radio_type=radio_type)
            result = {'layer': 'mac', 'cp': [mac_pkt], 'stdout': stdout + '\nNR MAC {}'.format(desc), 'ts': pkt_ts}

        return result

    def parse_nr_mac_rach_trigger(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0] if len(pkt_body) >= 4 else 0
        # A (new) RACH procedure means any connection-scoped RNTI we remembered
        # is stale: C-RNTIs are reassigned quickly on reconnect/handover.
        self.nr_last_c_rnti = 0
        stdout = 'NR MAC RACH Trigger v0x{:08x}: {}'.format(pkt_ver, util.xxd_oneline(pkt_body))
        return {'stdout': stdout, 'ts': pkt_ts}

    @staticmethod
    def nr_phr_db_str(v: int) -> str:
        # TS 38.133 Table 10.1.17.1-1 (same mapping as Wireshark's mac_nr_phr_fmt)
        if v == 0:
            return 'PH < -32 dB'
        if v == 63:
            return 'PH >= 38 dB'
        if v <= 54:
            return '{} dB <= PH < {} dB'.format(v - 33, v - 32)
        return '{} dB <= PH < {} dB'.format(22 + 2 * (v - 55), 24 + 2 * (v - 55))

    @staticmethod
    def nr_pcmax_dbm_str(v: int) -> str:
        # TS 38.133 Table 10.1.18.1-1 (same mapping as Wireshark's mac_nr_pcmax_f_c_fmt)
        if v == 0:
            return 'Pcmax < -29 dBm'
        if v == 63:
            return 'Pcmax >= 33 dBm'
        return '{} dBm <= Pcmax < {} dBm'.format(v - 30, v - 29)

    def parse_nr_l2_ul_tb(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        if len(pkt_body) < 8:
            return None
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]
        num_tti = pkt_body[4]
        stdout = 'NR L2 UL TB v0x{:08x}: num_tti={}'.format(pkt_ver, num_tti)
        off = 8
        for t in range(min(num_tti, 64)):
            if off + 8 > len(pkt_body):
                break
            slot = pkt_body[off]
            bits = int.from_bytes(pkt_body[off+1:off+8], 'big')
            fn = (bits >> 32) & 0x3ff
            num_tb = (bits >> 24) & 0xf
            if slot > 63 or num_tb > 8:
                # not a plausible TTI header; per-TB sub-structure not decoded yet
                break
            stdout += '\n  TTI slot={} SFN={} num_tb={}'.format(slot, fn, num_tb)
            off += 8
            for tb in range(min(num_tb, 16)):
                if off + 12 > len(pkt_body):
                    break
                grant_size = struct.unpack('<I', pkt_body[off+4:off+8])[0]
                bytes_build = struct.unpack('<I', pkt_body[off+8:off+12])[0]
                if grant_size > 100000 or bytes_build > 100000:
                    break
                stdout += '\n    TB: grant_size={} bytes_build={}'.format(grant_size, bytes_build)
                # TB header is followed by the built TB bytes; the exact per-version
                # sub-structure (per-LC packet info) is not decoded yet.
                off += 24 + bytes_build
        if self.parent and off < len(pkt_body):
            self.parent.logger.log(logging.DEBUG, 'NR L2 UL TB unparsed tail: {}'.format(util.xxd_oneline(pkt_body[off:])))

        # MAC CE scan for power headroom: the per-TB sub-structure layout varies by
        # firmware version, so locate Single Entry PHR CEs (UL-SCH LCID 57, subheader
        # byte 0x39) by pattern instead of the fixed walk above. Observed on SDXLEMUR
        # v0x00030004 as "3d 00 39 <ph> <pcmax>" (a Short-Truncated-BSR-style
        # subheader LCID 61 + CE, followed by the S-PHR CE); the CE bytes are the raw
        # MAC PDU bytes (cf. CellNinjia B872_cb_dcall.c). The weak pattern (a lone
        # 0x39 preceded by 0x00) also matched stray 0x39 bytes inside SDU payload and
        # zero padding of TBs on live captures, so it is reported on stdout only;
        # only the strong pattern is strong enough evidence to re-emit as a pcap
        # MAC-NR packet, and only while a C-RNTI is known (a NO_RNTI UL-SCH packet
        # would be mis-dissected by Wireshark as a BCCH/BCH PDU).
        cp = []
        for i in range(2, len(pkt_body) - 2):
            if pkt_body[i] != 0x39:
                continue
            strong = pkt_body[i-2:i] == b'\x3d\x00'
            weak = pkt_body[i-1] == 0x00 and (pkt_body[i+1] & 0xc0) == 0
            if not (strong or weak):
                continue
            # Single Entry PHR CE (38.321 6.1.3.32/6.1.3.16): PH byte (bits 5:0 =
            # PH, 38.133 Table 10.1.17.1-1) then Pcmax byte (bits 5:0 =
            # Pcmax,f,c, 38.133 Table 10.1.18.1-1). There is no P bit in NR
            # (that is LTE's extended PHR).
            ph_raw = pkt_body[i+1] & 0x3f
            pcmax_raw = pkt_body[i+2] & 0x3f
            stdout += '\n    S-PHR CE @{}: PH raw={} ({}), Pcmax,f,c raw={} ({}),{}'.format(
                i, ph_raw, self.nr_phr_db_str(ph_raw), pcmax_raw,
                self.nr_pcmax_dbm_str(pcmax_raw),
                ' strong' if strong else ' weak')
            # Re-emit the CE as a MAC-NR UL-SCH packet (subheader 0x39 + 2 CE bytes)
            if strong and self.nr_last_c_rnti:
                radio_type = util.mac_nr_radio_types.TDD_RADIO if self.nr_is_tdd() else util.mac_nr_radio_types.FDD_RADIO
                cp.append(util.create_nr_mac_gsmtap_packet(
                    pkt_ts, is_downlink=False,
                    rnti_type=util.mac_nr_rnti_types.C_RNTI, body=pkt_body[i:i+3],
                    rnti=self.nr_last_c_rnti, arfcn=self.nr_scell_dl_arfcn,
                    radio_type=radio_type))

        result = {'stdout': stdout, 'ts': pkt_ts}
        if cp:
            result['layer'] = 'mac'
            result['cp'] = cp
        return result

    def parse_nr_l2_ul_data_pdu(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        if len(pkt_body) < 8:
            return None
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]
        stdout = 'NR L2 UL Data PDU v0x{:08x}: {}'.format(pkt_ver, util.xxd_oneline(pkt_body))
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_l2_dl_data_pdu(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        if len(pkt_body) < 12:
            return None
        pkt_ver, num_tb = struct.unpack('<II', pkt_body[0:8])
        num_lcid = pkt_body[10]
        stdout = 'NR L2 DL Data PDU v0x{:08x}: num_tb={} num_lcid={}'.format(pkt_ver, num_tb, num_lcid)
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_l2_ul_bsr(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        stdout = 'NR L2 UL BSR: {}'.format(util.xxd_oneline(pkt_body))
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_mac_ul_tb_stats(self, pkt_header, pkt_body: bytes, args: dict):
        # 0xB881 NR5G MAC UL TB Stats, v0x00030001 (SDXLEMUR): S_H 12 bytes
        # (version u32, skip 3, num-records u8 @7, skip 4), then 80-byte records
        # of u32 fields (cf. CellNinjia NR5G_MAC_UL_TB_Stats.asn1, v196609).
        # Labels follow the vendor ASN.1: phr @32 is in milli-dB, max-power @40
        # is Pcmax in dBm (23 seen on this network), @68 is the number of UL
        # schedulings and @72 the number of no-scheduling occasions; @64 is an
        # unknown/skip field in the ASN.1 (skip5). The u16 pcmax @76 and the u16
        # flush-gap-cnt @78 close the record. @64 is unlabeled in the ASN.1
        # (0xfffffffe/0/24 seen live), so it is printed as a raw value.
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        if len(pkt_body) < 12:
            return None
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]
        num_records = pkt_body[7]
        stdout = 'NR MAC UL TB Stats v0x{:08x}: num_records={}'.format(pkt_ver, num_records)
        if pkt_ver != 0x00030001:
            stdout += ' (record layout below only verified for v0x00030001)'
        if self.parent:
            self.parent.logger.log(logging.DEBUG, 'NR MAC UL TB Stats raw: {}'.format(util.xxd_oneline(pkt_body)))
        off = 12
        for r in range(min(num_records, 16)):
            if off + 80 > len(pkt_body):
                break
            f = lambda o: struct.unpack('<I', pkt_body[off+o:off+o+4])[0]
            u16r = lambda o: struct.unpack('<H', pkt_body[off+o:off+o+2])[0]
            phr_raw = struct.unpack('<i', pkt_body[off+32:off+36])[0]
            stdout += ('\n  rec{}: tb_new_tx={} tb_retx={} num_mcs={} num_prb={} '
                       'PHR={:.3f} dB (raw {}) max_power(Pcmax)={} dBm '
                       'num_new_tx={} num_retx={} ri={} cqi={} num_phr={} '
                       'num_ulsch_sched={} num_no_ulsch_sched={} unk_rec64={} '
                       'pcmax={} flush_gap={}').format(
                r, f(0), f(8), f(16), f(24), phr_raw / 1000.0, phr_raw, f(40),
                f(44), f(48), f(52), f(56), f(60), f(68), f(72), f(64),
                u16r(76), u16r(78))
            off += 80
        return {'stdout': stdout, 'ts': pkt_ts}

    # TPC command field -> dB. The accumulated mappings are identical for PUSCH
    # and PUCCH: TS 38.213 Table 7.1.1-1 (PUSCH/SRS) and Table 7.2.1-1 (PUCCH).
    nr_tpc_db = {0: -1, 1: 0, 2: 1, 3: 3}

    def parse_nr_mac_dci_info(self, pkt_header, pkt_body: bytes, args: dict):
        # 0xB885 NR5G MAC DCI Info, v0x00030006 (SDXLEMUR): S_H 8 bytes
        # (version u32, skip 3, num-records u8 @7); then per record an 8-byte
        # R_H (slot u8 @0), then DCI entries: 4-byte DCI_H (dci-format =
        # (b0&1)<<1 | (b1&0x80)>>7; <2 = UL, >=2 = DL; rnti-type = (b1>>3)&0xf
        # -- bits 9-12 of the packed DCI_H header per CellNinjia
        # NR5G_MAC_DCI_Info.asn1) followed by a 24-byte DCI_UL (raw DCI payload
        # 12B, then bit-packed fields per the same ASN.1) or 8-byte DCI_DL.
        # pusch-tpc = (DCI_UL[12] >> 3) & 3  -> closed-loop PUSCH power control.
        # Note: per-record DCI counts are not decoded, so with num-records > 1
        # all DCI entries end up attributed to the first record.
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        if len(pkt_body) < 8:
            return None
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]
        num_records = pkt_body[7]
        stdout = 'NR MAC DCI Info v0x{:08x}: num_records={}'.format(pkt_ver, num_records)
        if num_records > 1:
            stdout += ' (multi-record DCI attribution unverified)'
        if self.parent:
            self.parent.logger.log(logging.DEBUG, 'NR MAC DCI Info raw: {}'.format(util.xxd_oneline(pkt_body)))
        off = 8
        for r in range(min(num_records, 16)):
            if off + 8 > len(pkt_body):
                break
            slot = pkt_body[off]
            off += 8  # R_H
            stdout += '\n  rec{} slot={}'.format(r, slot)
            ndci = 0
            while off + 4 <= len(pkt_body) and ndci < 32:
                fmt = ((pkt_body[off] & 0x01) << 1) | ((pkt_body[off+1] & 0x80) >> 7)
                rnti_type = (pkt_body[off+1] >> 3) & 0x0f
                body_off = off + 4
                if fmt < 2:  # UL grant (DCI format 0_0 / 0_1)
                    if body_off + 24 > len(pkt_body):
                        break
                    b12, b13, b14 = pkt_body[body_off+12], pkt_body[body_off+13], pkt_body[body_off+14]
                    tpc = (b12 >> 3) & 0x03
                    harq = ((b12 & 0x01) << 1) | (b13 >> 7)
                    rv = (b13 >> 5) & 0x03
                    # mcs is the 5-bit UPER integer at bits 12-16 of the packed
                    # region: high nibble of b13 plus the MSB of b14
                    mcs = ((b13 & 0x0f) << 1) | ((b14 >> 7) & 0x01)
                    ndi = (b14 >> 6) & 0x01
                    rb = struct.unpack('>H', pkt_body[body_off+16:body_off+18])[0]
                    stdout += ('\n    DCI UL rnti_type={} PUSCH-TPC={} ({:+d} dB) harq={} rv={} '
                               'mcs={} ndi={} rb_raw=0x{:04x} raw_dci={}').format(
                        rnti_type, tpc, self.nr_tpc_db.get(tpc, 0), harq, rv, mcs, ndi, rb,
                        pkt_body[body_off:body_off+12].hex())
                    off = body_off + 24
                else:  # DL assignment (DCI format 1_0 / 1_1)
                    if body_off + 8 > len(pkt_body):
                        break
                    tpc_pucch = pkt_body[body_off+2] & 0x03
                    stdout += ('\n    DCI DL rnti_type={} PUCCH-TPC={} ({:+d} dB) raw={}').format(
                        rnti_type, tpc_pucch, self.nr_tpc_db.get(tpc_pucch, 0),
                        pkt_body[body_off:body_off+8].hex())
                    off = body_off + 8
                ndci += 1
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_mac_ul_phys_chan_sched(self, pkt_header, pkt_body: bytes, args: dict):
        # 0xB883 NR5G MAC UL Physical Channel Schedule Report: per-grant PUSCH
        # scheduling (rb-start/num-rb/mcs/tb-size). Layout is UPER bit-packed per
        # CellNinjia NR5G_MAC_UL_Physical_Channel_Schedule_Report_v196623.asn1;
        # only the version header is decoded here, raw bytes at DEBUG level.
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        if self.parent:
            self.parent.logger.log(logging.DEBUG, 'NR MAC UL Phys Chan Sched raw: {}'.format(util.xxd_oneline(pkt_body)))
        stdout = 'NR MAC UL Phys Chan Sched v0x{:08x}: {}'.format(struct.unpack('<I', pkt_body[0:4])[0] if len(pkt_body) >= 4 else 0, util.xxd_oneline(pkt_body))
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_mac_dl_tb_report(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        if len(pkt_body) < 4:
            return None
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]
        stdout = 'NR MAC DL TB Report v0x{:08x}: {}'.format(pkt_ver, util.xxd_oneline(pkt_body))
        return {'stdout': stdout, 'ts': pkt_ts}

    # RRC
    def parse_nr_mib_info(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_ver = self.nr_pkt_ver._make(struct.unpack('<HH', pkt_body[0:4]))

        item_struct = namedtuple('QcDiagNrMibInfo', 'pci nrarfcn')
        scs_map = {
            0: 15,
            1: 30,
            2: 60,
            3: 120,
        }

        scs_str = ''
        if pkt_ver.rel_maj == 0x00 and pkt_ver.rel_min == 0x03: # Version 3
            item = item_struct._make(struct.unpack('<HI', pkt_body[4:10]))
            props_bits = bitstring.Bits(bytes=reversed(pkt_body[10:14]))
            sfn = props_bits[0:10].uint
            scs = props_bits[30:32].uint
        elif pkt_ver.rel_maj == 0x02 and pkt_ver.rel_min == 0x00: # Version 131072
            item = item_struct._make(struct.unpack('<HI', pkt_body[4:10]))
            props_bits = bitstring.Bits(bytes=reversed(pkt_body[10:15]))
            sfn = props_bits[0:10].uint
            scs = props_bits[31:33].uint
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR MIB Information packet, version {}.{}'.format(pkt_ver.rel_maj, pkt_ver.rel_min))
                self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return

        if scs in scs_map:
            scs_str = '{} kHz'.format(scs_map[scs])

        if len(scs_str) > 0:
            stdout = 'NR MIB: NR-ARFCN: {}, PCI: {:4d}, SFN: {}, SCS: {}'.format(item.nrarfcn, item.pci, sfn, scs_str)
        else:
            stdout = 'NR MIB: NR-ARFCN: {}, PCI: {:4d}, SFN: {}'.format(item.nrarfcn, item.pci, sfn)
        # See parse_nr_ml1_meas_db_update: learn the serving NR-ARFCN early so
        # MAC-NR emissions can tell TDD from FDD before 0xB823 is seen.
        if not self.nr_scell_dl_arfcn and item.nrarfcn:
            self.nr_scell_dl_arfcn = item.nrarfcn
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_rrc_scell_info(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_ver = self.nr_pkt_ver._make(struct.unpack('<HH', pkt_body[0:4]))

        item_struct = namedtuple('QcDiagNrScellInfo', 'pci dl_nrarfcn ul_nrarfcn dl_bandwidth ul_bandwidth cell_id mcc mnc_digit mnc allowed_access tac band')
        item_struct_v30000 = namedtuple('QcDiagNrScellInfoV30000', 'pci nr_cgi dl_nrarfcn ul_nrarfcn dl_bandwidth ul_bandwidth cell_id mcc mnc_digit mnc allowed_access tac band')
        if pkt_ver.rel_maj == 0x00 and pkt_ver.rel_min == 0x04:
            # PCI 2b, DL NR-ARFCN 4b, UL NR-ARFCN 4b, DLBW 2b, ULBW 2b, Cell ID 8b, MCC 2b, MCC digit 1b, MNC 2b, MNC digit 1b, TAC 4b, ?
            item = item_struct._make(struct.unpack('<H LLHH Q H BH B LH', pkt_body[4:38]))
        elif pkt_ver.rel_maj == 0x03:
            if pkt_ver.rel_min == 0x00:
                # PCI 2b, NR CGI 8b, DL NR-ARFCN 4b, UL NR-ARFCN 4b, DLBW 2b, ULBW 2b, Cell ID 8b, MCC 2b, MCC digit 1b, MNC 2b, MNC digit 1b, TAC 4b, ?
                item = item_struct_v30000._make(struct.unpack('<H Q LLHH Q H BH B LH', pkt_body[4:46]))
            elif pkt_ver.rel_min == 0x04:
                # Version 3.4: 4-byte prefix (observed 01 00 01 00), then the same payload as version 3.0
                if len(pkt_body) < 50:
                    if self.parent:
                        self.parent.logger.log(logging.WARNING, 'Truncated NR RRC SCell Information packet, version {}.{}'.format(pkt_ver.rel_maj, pkt_ver.rel_min))
                    return None
                item = item_struct_v30000._make(struct.unpack('<H Q LLHH Q H BH B LH', pkt_body[8:50]))
            elif pkt_ver.rel_min in (0x02, 0x03, ):
                # ? 3b, PCI 2b, NR CGI 8b, DL NR-ARFCN 4b, UL NR-ARFCN 4b, DLBW 2b, ULBW 2b, Cell ID 8b, MCC 2b, MCC digit 1b, MNC 2b, MNC digit 1b, TAC 4b, ?
                item = item_struct_v30000._make(struct.unpack('<H Q LLHH Q H BH B LH', pkt_body[7:49]))
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Unknown NR RRC SCell Information packet, version {}.{}'.format(pkt_ver.rel_maj, pkt_ver.rel_min))
                    self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
                return None
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR RRC SCell Information packet, version {}.{}'.format(pkt_ver.rel_maj, pkt_ver.rel_min))
                self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return None

        if self.display_format == 'd':
            tac_cid_fmt = 'TAC/CID: {}/{}'.format(item.tac, item.cell_id)
        elif self.display_format == 'x':
            tac_cid_fmt = 'xTAC/xCID: {:x}/{:x}'.format(item.tac, item.cell_id)
        elif self.display_format == 'b':
            tac_cid_fmt = 'TAC/CID: {}/{} ({:#x}/{:#x})'.format(item.tac, item.cell_id, item.tac, item.cell_id)
        else:
            tac_cid_fmt = 'xTAC/xCID: {:x}/{:x}'.format(item.tac, item.cell_id)

        if item.mnc_digit == 2:
            stdout = 'NR RRC SCell Info: NR-ARFCN: {}/{}, Bandwidth: {}/{} MHz, Band: {}, PCI: {:4d}, MCC: {}, MNC: {:02}, {}'.format(item.dl_nrarfcn,
                item.ul_nrarfcn, item.dl_bandwidth, item.ul_bandwidth, item.band, item.pci, item.mcc, item.mnc, tac_cid_fmt)
        elif item.mnc_digit == 3:
            stdout = 'NR RRC SCell Info: NR-ARFCN: {}/{}, Bandwidth: {}/{} MHz, Band: {}, PCI: {:4d}, MCC: {}, MNC: {:03}, {}'.format(item.dl_nrarfcn,
                item.ul_nrarfcn, item.dl_bandwidth, item.ul_bandwidth, item.band, item.pci, item.mcc, item.mnc, tac_cid_fmt)
        else:
            stdout = 'NR RRC SCell Info: NR-ARFCN: {}/{}, Bandwidth: {}/{} MHz, Band: {}, PCI: {:4d}, MCC: {}, MNC: {}, {}'.format(item.dl_nrarfcn,
                item.ul_nrarfcn, item.dl_bandwidth, item.ul_bandwidth, item.band, item.pci, item.mcc, item.mnc, tac_cid_fmt)
        self.nr_scell_dl_arfcn = item.dl_nrarfcn
        self.nr_scell_ul_arfcn = item.ul_nrarfcn
        self.nr_scell_band = item.band
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_rrc_conf_info(self, pkt_header, pkt_body: bytes, args: dict):
        pass

    def parse_nr_rrc(self, pkt_header, pkt_body: bytes, args: dict):
        msg_content = b''
        stdout = ''
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]
        item_struct = namedtuple('QcDiagNrRrcOtaPacket', 'rrc_rel_maj rrc_rel_min rbid pci nrarfcn sfn_subfn pdu_id sib_mask len')
        item_struct_v17 = namedtuple('QcDiagNrRrcOtaPacketV17', 'rrc_rel_maj rrc_rel_min rbid pci ncgi nrarfcn sfn_subfn pdu_id sib_mask len')
        item_struct_v19 = namedtuple('QcDiagNrRrcOtaPacketV19', 'rrc_rel_maj rrc_rel_min rbid pci ncgi nrarfcn sfn_subfn pdu_id sib_mask len unk1')
        item_struct_v23 = namedtuple('QcDiagNrRrcOtaPacketV23', 'rrc_rel_maj rrc_rel_min rbid pci ncgi nrarfcn sfn_subfn pdu_id sib_mask len unk1 unk2 unk3 segment_id')

        if pkt_ver in (0x09, ): # Version 9
            item = item_struct._make(struct.unpack('<BBBHIIBIH', pkt_body[4:24]))
            msg_content = pkt_body[24:]
        elif pkt_ver in (0x0c, 0x0e): # Version 12, 14
            item = item_struct._make(struct.unpack('<BBBHI3sBIH', pkt_body[4:23]))
            msg_content = pkt_body[23:]
        elif pkt_ver in (0x11, ): # Version 17
            item = item_struct_v17._make(struct.unpack('<BBBH Q I3sBIH', pkt_body[4:31]))
            msg_content = pkt_body[31:]
        elif pkt_ver in (0x13, 0x14, 0x19): # Version 19, 20, 25
            item = item_struct_v19._make(struct.unpack('<BBBH Q I3sBIHB', pkt_body[4:32]))
            msg_content = pkt_body[32:]
        elif pkt_ver in (0x17, 0x18, 0x1a, 0x1c): # Version 23, 24, 26, 28
            item = item_struct_v23._make(struct.unpack('<BBBH Q I3sBIHBBBB', pkt_body[4:35]))
            msg_content = pkt_body[35:]
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR RRC OTA Message packet version {:#x}'.format(pkt_ver))
                self.parent.logger.log(logging.DEBUG, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return None

        if isinstance(item, item_struct_v17) or isinstance(item, item_struct_v19) or isinstance(item, item_struct_v23):
            try:
                ncgi = bitstring.Bits(uint=item.ncgi, length=60)
            except bitstring.exceptions.CreationError:
                # Telit FN990 and others: invalid or logically unfit NR CGI is created, which does not fit in 60 bytes
                ncgi = None
        else:
            ncgi = None

        if isinstance(item, item_struct_v23):
            if item.segment_id == 0:
                # Not segmented RRC, check previously cached
                pass
            elif item.segment_id in range(1, 7):
                # Part of the segment, leading is 1
                self.rrc_segments[item.segment_id] = msg_content
                self.first_segment_item = item
                return None
            elif item.segment_id == 7:
                # End of segmented RRC
                segment_joined = b''
                for i in range(1, 7):
                    if i in self.rrc_segments:
                        segment_joined += self.rrc_segments[i]
                segment_joined += msg_content
                msg_content = segment_joined
                self.rrc_segments = dict()
                self.first_segment_item = None

        if pkt_ver in (0x09, 0x0c):
            rrc_type_map = {
                1: util.gsmtapv3_nr_rrc_types.BCCH_BCH,
                2: util.gsmtapv3_nr_rrc_types.BCCH_DL_SCH,
                3: util.gsmtapv3_nr_rrc_types.DL_CCCH,
                4: util.gsmtapv3_nr_rrc_types.DL_DCCH,
                5: util.gsmtapv3_nr_rrc_types.PCCH,
                6: util.gsmtapv3_nr_rrc_types.UL_CCCH,
                7: util.gsmtapv3_nr_rrc_types.UL_CCCH1,
                8: util.gsmtapv3_nr_rrc_types.UL_DCCH,
                9: util.gsmtapv3_nr_rrc_types.RRC_RECONF,
                10: util.gsmtapv3_nr_rrc_types.RRC_RECONF_COMPLETE,
                28: util.gsmtapv3_nr_rrc_types.UE_MRDC_CAP,
                29: util.gsmtapv3_nr_rrc_types.UE_NR_CAP
            }
            rrc_type_map_stdout = {
                25: "nr-RadioBearerConfig",
            }
        elif pkt_ver in (0x0e, ):
            rrc_type_map = {
                1: util.gsmtapv3_nr_rrc_types.BCCH_BCH,
                2: util.gsmtapv3_nr_rrc_types.BCCH_DL_SCH,
                3: util.gsmtapv3_nr_rrc_types.DL_CCCH,
                4: util.gsmtapv3_nr_rrc_types.DL_DCCH,
                5: util.gsmtapv3_nr_rrc_types.PCCH,
                6: util.gsmtapv3_nr_rrc_types.UL_CCCH,
                7: util.gsmtapv3_nr_rrc_types.UL_CCCH1,
                8: util.gsmtapv3_nr_rrc_types.UL_DCCH,
                9: util.gsmtapv3_nr_rrc_types.RRC_RECONF,
                10: util.gsmtapv3_nr_rrc_types.RRC_RECONF_COMPLETE,
                31: util.gsmtapv3_nr_rrc_types.UE_MRDC_CAP,
                32: util.gsmtapv3_nr_rrc_types.UE_NR_CAP,
                33: util.gsmtapv3_nr_rrc_types.UE_NR_CAP
            }
            rrc_type_map_stdout = {
                28: "nr-RadioBearerConfig",
            }
        elif pkt_ver in (0x11, 0x13, 0x19):
            rrc_type_map = {
                1: util.gsmtapv3_nr_rrc_types.BCCH_BCH,
                2: util.gsmtapv3_nr_rrc_types.BCCH_DL_SCH,
                3: util.gsmtapv3_nr_rrc_types.DL_CCCH,
                4: util.gsmtapv3_nr_rrc_types.DL_DCCH,
                5: util.gsmtapv3_nr_rrc_types.PCCH,
                6: util.gsmtapv3_nr_rrc_types.UL_CCCH,
                7: util.gsmtapv3_nr_rrc_types.UL_CCCH1,
                8: util.gsmtapv3_nr_rrc_types.UL_DCCH,
                9: util.gsmtapv3_nr_rrc_types.RRC_RECONF,
                10: util.gsmtapv3_nr_rrc_types.RRC_RECONF_COMPLETE,
            }
            rrc_type_map_stdout = {
                29: "nr-RadioBearerConfig",
            }
        elif pkt_ver in (0x14, 0x17, 0x18):
           rrc_type_map = {
                1: util.gsmtapv3_nr_rrc_types.BCCH_BCH,
                2: util.gsmtapv3_nr_rrc_types.BCCH_DL_SCH,
                3: util.gsmtapv3_nr_rrc_types.DL_CCCH,
                4: util.gsmtapv3_nr_rrc_types.DL_DCCH,
                5: util.gsmtapv3_nr_rrc_types.MCCH,
                6: util.gsmtapv3_nr_rrc_types.PCCH,
                7: util.gsmtapv3_nr_rrc_types.UL_CCCH,
                8: util.gsmtapv3_nr_rrc_types.UL_CCCH1,
                9: util.gsmtapv3_nr_rrc_types.UL_DCCH,
                10: util.gsmtapv3_nr_rrc_types.RRC_RECONF,
                11: util.gsmtapv3_nr_rrc_types.RRC_RECONF_COMPLETE,
           }
           rrc_type_map_stdout = {
                36: "nr-RadioBearerConfig",
            }
        elif pkt_ver in (0x1a, ):
           rrc_type_map = {
                1: util.gsmtapv3_nr_rrc_types.BCCH_BCH,
                2: util.gsmtapv3_nr_rrc_types.BCCH_DL_SCH,
                3: util.gsmtapv3_nr_rrc_types.DL_CCCH,
                4: util.gsmtapv3_nr_rrc_types.DL_DCCH,
                5: util.gsmtapv3_nr_rrc_types.MCCH,
                6: util.gsmtapv3_nr_rrc_types.PCCH,
                7: util.gsmtapv3_nr_rrc_types.UL_CCCH,
                8: util.gsmtapv3_nr_rrc_types.UL_CCCH1,
                9: util.gsmtapv3_nr_rrc_types.UL_DCCH,
                11: util.gsmtapv3_nr_rrc_types.RRC_RECONF,
                12: util.gsmtapv3_nr_rrc_types.RRC_RECONF_COMPLETE,
           }
           rrc_type_map_stdout = {
                36: "nr-RadioBearerConfig",
            }
        elif pkt_ver in (0x1c, ):
           rrc_type_map = {
                1: util.gsmtapv3_nr_rrc_types.BCCH_BCH,
                2: util.gsmtapv3_nr_rrc_types.BCCH_DL_SCH,
                3: util.gsmtapv3_nr_rrc_types.DL_CCCH,
                4: util.gsmtapv3_nr_rrc_types.DL_DCCH,
                5: util.gsmtapv3_nr_rrc_types.MCCH,
                6: util.gsmtapv3_nr_rrc_types.PCCH,
                7: util.gsmtapv3_nr_rrc_types.UL_CCCH,
                8: util.gsmtapv3_nr_rrc_types.UL_CCCH1,
                9: util.gsmtapv3_nr_rrc_types.UL_DCCH,
                10: util.gsmtapv3_nr_rrc_types.UL_DCCH,
                11: util.gsmtapv3_nr_rrc_types.RRC_RECONF,
                12: util.gsmtapv3_nr_rrc_types.RRC_RECONF_COMPLETE,
           }
           rrc_type_map_stdout = {
                36: "nr-RadioBearerConfig",
            }

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if item.pdu_id in rrc_type_map.keys():
            type_str = rrc_type_map[item.pdu_id]
            gsmtapv3_metadata = dict()
            gsmtapv3_metadata[util.gsmtapv3_metadata_tags.BSIC_PSC_PCI] = item.pci
            if ncgi:
                mcc_mnc = util.unpack_mcc_mnc(ncgi[36:60].bytes)
                cell_id = ncgi[0:36].uint
                if self.display_format == 'd':
                    stdout += ', NR CGI: {}-{}-{}'.format(mcc_mnc[0], mcc_mnc[1], cell_id)
                elif self.display_format == 'x':
                    stdout += ', NR CGI: {}-{}-{:9x}'.format(mcc_mnc[0], mcc_mnc[1], cell_id)
                elif self.display_format == 'b':
                    stdout += ', NR CGI: {}-{}-{} ({:#9x})'.format(mcc_mnc[0], mcc_mnc[1], cell_id, cell_id)
                else:
                    stdout += ', NR CGI: {}-{}-{:9x}'.format(mcc_mnc[0], mcc_mnc[1], cell_id)
            nr_pdu_id_gsmtap = rrc_type_map[item.pdu_id]

            gsmtap_hdr = util.create_gsmtap_header(
                version = 3,
                payload_type = util.gsmtapv3_types.NR_RRC,
                arfcn = item.nrarfcn,
                sub_type = nr_pdu_id_gsmtap,
                device_sec = ts_sec,
                device_usec = ts_usec,
                metadata = gsmtapv3_metadata)

            return {'layer': 'rrc', 'cp': [gsmtap_hdr + msg_content], 'ts': pkt_ts}
        else:
            if item.pdu_id in rrc_type_map_stdout.keys():
                type_str = rrc_type_map_stdout[item.pdu_id]
            else:
                type_str = '{}'.format(item.pdu_id)

            stdout += "NR RRC OTA Packet: NR-ARFCN: {}, PCI: {}, Type: {}\n".format(item.nrarfcn, item.pci, type_str)
            stdout += "NR RRC OTA Packet: Body: {}".format(binascii.hexlify(msg_content).decode())

            return {'layer': 'rrc', 'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_cacombos(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        if self.parent:
            if not self.parent.cacombos:
                return None

        return {'stdout': 'NR UE CA Combos Raw: {}'.format(binascii.hexlify(pkt_body).decode()), 'ts': pkt_ts}

    # NAS
    def parse_nr_mm_state(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_ver = self.nr_pkt_ver._make(struct.unpack('<HH', pkt_body[0:4]))

        if (pkt_ver.rel_maj == 0x00 and pkt_ver.rel_min == 0x01) or (pkt_ver.rel_maj == 0x03 and pkt_ver.rel_min == 0x00): # Version 1 and 196608
            item_struct = namedtuple('QcDiagNrNasMmState', 'mm_state mm_substate plmn_id guti_5gs mm_update_status tac')
            item = item_struct._make(struct.unpack('<BH3s12sb3s', pkt_body[4:26]))
            plmn_id = util.unpack_mcc_mnc(item.plmn_id)
            tac = struct.unpack('>L', b'\x00'+item.tac)[0]

            if item.guti_5gs[0] == 0x02:
                # mcc-mcc-amf_rid-amf_sid-amf_ptr-5g_tmsi
                plmn_id_guti = util.unpack_mcc_mnc(item.guti_5gs[1:4])
                amf_sid = struct.unpack('<H', item.guti_5gs[5:7])[0]
                tmsi_5gs = struct.unpack('<L', item.guti_5gs[8:12])[0]
                guti_str = '{}-{}-{:02x}-{:03x}-{:02x}-{:08x}'.format(plmn_id_guti[0], plmn_id_guti[1], item.guti_5gs[4],
                                                              amf_sid, item.guti_5gs[7], tmsi_5gs)
            else:
                guti_str = binascii.hexlify(item.guti_5gs).decode()

            if self.display_format == 'd':
                stdout = '5GMM State: {}/{}/{}, MCC/MNC: {}/{}, TAC: {}, GUTI: {}'.format(
                    item.mm_state, item.mm_substate, item.mm_update_status, plmn_id[0], plmn_id[1], tac, guti_str
                )
            elif self.display_format == 'x':
                stdout = '5GMM State: {}/{}/{}, MCC/MNC: {}/{}, TAC: {:6x}, GUTI: {}'.format(
                    item.mm_state, item.mm_substate, item.mm_update_status, plmn_id[0], plmn_id[1], tac, guti_str
                )
            elif self.display_format == 'b':
                stdout = '5GMM State: {}/{}/{}, MCC/MNC: {}/{}, TAC: {} ({:#6x}), GUTI: {}'.format(
                    item.mm_state, item.mm_substate, item.mm_update_status, plmn_id[0], plmn_id[1], tac, tac, guti_str
                )
            else:
                stdout = '5GMM State: {}/{}/{}, MCC/MNC: {}/{}, TAC: {:6x}, GUTI: {}'.format(
                    item.mm_state, item.mm_substate, item.mm_update_status, plmn_id[0], plmn_id[1], tac, guti_str
                )
            return {'stdout': stdout, 'ts': pkt_ts}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR MM State packet, version {}.{}'.format(pkt_ver.rel_maj, pkt_ver.rel_min))
                self.parent.logger.log(logging.WARNING, "Body: %s" % (util.xxd_oneline(pkt_body[4:])))
            return

    def parse_nr_nas(self, pkt_header, pkt_body: bytes, args: dict, cmd_id: int):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        stdout = ''
        plain = (cmd_id in (0xB800, 0xB801, 0xB80A, 0xB80B, 0xB814))

        # Version 4b, std version maj.min.rev 1b each
        pkt_ver = struct.unpack('<L', pkt_body[0:4])[0]
        item_struct = namedtuple('QcDiagNrNasMsg', 'vermaj vermid vermin')
        msg_content = pkt_body[7:]
        if pkt_ver == 0x1:
            item = item_struct._make(struct.unpack('<BBB', pkt_body[4:7]))
            stdout = "NAS-5GS message ({:04X}) version {:x}.{:x}.{:x}".format(cmd_id, item.vermaj, item.vermid, item.vermin)
            msg_content = pkt_body[7:]

            gsmtap_hdr = util.create_gsmtap_header(
                version = 3,
                payload_type = util.gsmtapv3_types.NAS_5GS,
                arfcn = 0,
                sub_type = 0 if plain else 1,
                device_sec = ts_sec,
                device_usec = ts_usec)

            return {'layer': 'nas', 'cp': [gsmtap_hdr + msg_content], 'ts': pkt_ts, 'stdout': stdout}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR NAS Message packet version {:#x}'.format(pkt_ver))
                self.parent.logger.log(logging.DEBUG, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return None
