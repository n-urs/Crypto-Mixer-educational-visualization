#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import os, math, csv, hashlib, random, traceback
from typing import Dict, List, Tuple, Any, Optional, Iterable
from datetime import datetime, timezone
from decimal import Decimal, getcontext, ROUND_HALF_UP

# ---------- Decimal helpers (two decimals) ----------
getcontext().prec = 28
TWOPLACES = Decimal("0.01")
ZERO = Decimal("0.00")

def D(x) -> Decimal:
    """Exact Decimal from str/number."""
    if isinstance(x, Decimal):
        return x
    return Decimal(str(x))

def q2(x) -> Decimal:
    """Quantize to 2 decimals, ROUND_HALF_UP."""
    return D(x).quantize(TWOPLACES, rounding=ROUND_HALF_UP)

def fmt2(x) -> str:
    """String with exactly two decimals."""
    return f"{q2(x):.2f}"

# ---------- Paths & logging ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
def pjoin(fn): return os.path.join(BASE_DIR, fn)

import logging
from logging.handlers import RotatingFileHandler
LOG_PATH = pjoin("mixer.log")
LOG_FMT = "%(asctime)sZ | %(levelname)-7s | %(name)s | %(funcName)s:%(lineno)d | %(message)s"
class _UTCFormatter(logging.Formatter):
    converter = staticmethod(lambda *_: datetime.now(timezone.utc).timetuple())
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mixer")
logger.setLevel(logging.INFO)
if not logger.handlers or not any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
    fh = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(_UTCFormatter(LOG_FMT, "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(fh)
logger.info("===== PyQt6 mixer starting =====")

# ---------- Data utils ----------
def utc_now_str(): return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
def sha256(x: bytes) -> bytes: return hashlib.sha256(x).digest()
def hexb(b: bytes) -> str: return b.hex()
def make_secret() -> bytes: return os.urandom(32)
def make_commitment(secret: bytes, nonce: bytes = b'') -> bytes: return hashlib.sha256(secret + nonce).digest()

# ---------- Merkle tree ----------
class MerkleTree:
    def __init__(self):
        self.leaves: List[bytes] = []
        self.layers: List[List[bytes]] = []

    def add_leaf(self, leaf: bytes):
        self.leaves.append(leaf)
        self._rebuild()

    def _rebuild(self):
        layers = []
        cur = self.leaves[:]
        layers.append(cur)
        while len(cur) > 1:
            if len(cur) % 2 == 1:
                cur = cur + [cur[-1]]
            nxt = []
            for i in range(0, len(cur), 2):
                nxt.append(sha256(cur[i] + cur[i+1]))
            cur = nxt
            layers.append(cur)
        self.layers = layers

    def root(self) -> bytes:
        if not self.layers:
            return b'\x00' * 32
        return self.layers[-1][0]

    def get_proof(self, index: int) -> List[Tuple[bytes, bool]]:
        proof = []
        if index < 0 or index >= len(self.leaves):
            raise IndexError("leaf index out of range")
        for layer in self.layers[:-1]:
            L = layer[:]
            if len(L) % 2 == 1:
                L = L + [L[-1]]
            pair_index = index ^ 1
            is_left = (pair_index % 2 == 0)
            proof.append((L[pair_index], is_left))
            index //= 2
        return proof

    @staticmethod
    def verify_proof(leaf: bytes, proof: List[Tuple[bytes, bool]], root: bytes) -> bool:
        cur = leaf
        for sibling, is_left in proof:
            cur = sha256(sibling + cur) if is_left else sha256(cur + sibling)
        return cur == root

# ---------- Mixer core (Decimal balances) ----------
class ToyMixer:
    def __init__(self):
        self.tree = MerkleTree()
        self.commit_to_index: Dict[str, int] = {}
        self.commit_amount: Dict[str, Decimal] = {}
        self.spent: set[str] = set()
        self.ledger: Dict[str, Decimal] = {}
        self.pool_coins: Decimal = ZERO
        logger.info("ToyMixer initialized")

    def _add_commitment(self, amount: Decimal) -> Tuple[str, bytes]:
        amount = q2(amount)
        sec = make_secret()
        com = make_commitment(sec)
        ch = hexb(com)
        if ch in self.commit_to_index:
            return self._add_commitment(amount)
        self.tree.add_leaf(com)
        idx = len(self.tree.leaves) - 1
        self.commit_to_index[ch] = idx
        self.commit_amount[ch] = amount
        logger.info(f"Change note added: {ch[:16]}… amount={fmt2(amount)} index={idx}")
        return ch, sec

    def deposit(self, secret: bytes, from_addr: str, amount: Decimal) -> str:
        amount = q2(amount)
        if amount <= ZERO: raise ValueError("amount must be positive")
        if self.ledger.get(from_addr, ZERO) < amount: raise ValueError("insufficient balance")
        com = make_commitment(secret); ch = hexb(com)
        if ch in self.commit_to_index: raise ValueError("commitment already exists")
        self.ledger[from_addr] = q2(self.ledger.get(from_addr, ZERO) - amount)
        self.pool_coins = q2(self.pool_coins + amount)
        self.tree.add_leaf(com)
        idx = len(self.tree.leaves) - 1
        self.commit_to_index[ch] = idx
        self.commit_amount[ch] = amount
        logger.info(f"Deposit: addr={from_addr[:10]}… amount={fmt2(amount)} commit={ch[:16]}… idx={idx} root={hexb(self.tree.root())[:16]}…")
        return ch

    def withdraw(
        self, secret: bytes, to_addr: str, amount: Decimal, *,
        commission_percent: float = 0.0,
        profit_addr: Optional[str] = None
    ) -> Tuple[Decimal, str, list, Decimal, Decimal]:
        """
        Returns: (withdrawn_gross, spent_commit_hex, change_list, fee, net_to_recipient)
        Pool is reduced by 'withdrawn_gross'. Recipient gets 'net'. Fee goes to profit_addr.
        """
        amount = q2(amount)
        if amount <= ZERO: return ZERO, "", [], ZERO, ZERO
        com = make_commitment(secret); ch = hexb(com)
        if ch not in self.commit_to_index:
            logger.warning("withdraw: commitment not found"); return ZERO, "", [], ZERO, ZERO
        if ch in self.spent:
            logger.warning("withdraw: already spent"); return ZERO, "", [], ZERO, ZERO
        idx = self.commit_to_index[ch]
        if not MerkleTree.verify_proof(com, self.tree.get_proof(idx), self.tree.root()):
            logger.warning("withdraw: invalid proof"); return ZERO, "", [], ZERO, ZERO
        avail = self.commit_amount.get(ch, ZERO)
        if amount > avail:
            logger.warning(f"withdraw: req {fmt2(amount)} > avail {fmt2(avail)}"); return ZERO, "", [], ZERO, ZERO
        if self.pool_coins < amount:
            logger.error("withdraw: pool insufficient"); return ZERO, "", [], ZERO, ZERO

        # commission (Decimal)
        pct = D(commission_percent)
        fee = q2(amount * pct / D(100))
        fee = max(ZERO, min(fee, amount))
        net = q2(amount - fee)

        # apply
        self.spent.add(ch)
        self.pool_coins = q2(self.pool_coins - amount)
        self.ledger[to_addr] = q2(self.ledger.get(to_addr, ZERO) + net)
        if profit_addr:
            self.ledger.setdefault(profit_addr, ZERO)
            self.ledger[profit_addr] = q2(self.ledger[profit_addr] + fee)

        change_list = []
        if avail > amount:
            chg_amt = q2(avail - amount)
            chg_hex, chg_sec = self._add_commitment(chg_amt)
            change_list.append((chg_hex, chg_amt, chg_sec))

        logger.info(
            f"Withdraw: to={to_addr[:10]}… gross={fmt2(amount)} fee={fmt2(fee)} net={fmt2(net)} "
            f"spent={ch[:16]}… change={len(change_list)}"
        )
        return amount, ch, change_list, fee, net

    def balance_of(self, addr: str) -> Decimal:
        return q2(self.ledger.get(addr, ZERO))

    def send(self, frm: str, to: str, amount: Decimal) -> bool:
        amount = q2(amount)
        if amount <= ZERO: return False
        if self.ledger.get(frm, ZERO) < amount: return False
        self.ledger[frm] = q2(self.ledger.get(frm, ZERO) - amount)
        self.ledger[to] = q2(self.ledger.get(to, ZERO) + amount)
        logger.info(f"Send: {fmt2(amount)} from {frm[:10]}… to {to[:10]}…")
        return True

# ============================ PyQt6 UI ============================
from PyQt6.QtCore import Qt, QTimer, QRectF, QPointF, QAbstractTableModel, QModelIndex
from PyQt6.QtGui import QBrush, QPen, QColor, QPolygonF, QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QGridLayout, QGroupBox,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsTextItem,
    QGraphicsLineItem, QGraphicsPolygonItem, QGraphicsRectItem, QLabel,
    QLineEdit, QPushButton, QSplitter, QTableView, QSizePolicy, QSpinBox, QDoubleSpinBox
)

# ---------- Table model ----------
class SimpleTableModel(QAbstractTableModel):
    def __init__(self, headers: List[str], rows: List[List[Any]]):
        super().__init__()
        self.headers = headers
        self.rows = rows
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int: return len(self.rows)
    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int: return len(self.headers)
    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid(): return None
        if role == Qt.ItemDataRole.DisplayRole:
            v = self.rows[index.row()][index.column()]
            return "" if v is None else str(v)
        return None
    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole:
            if orientation == Qt.Orientation.Horizontal: return self.headers[section]
            else: return str(section)
        return None

# ---------- Graphics helpers ----------
def arrow_item(x1, y1, x2, y2, color: QColor, width: float = 2.0):
    line = QGraphicsLineItem(x1, y1, x2, y2)
    line.setPen(QPen(color, width))
    dx, dy = x2 - x1, y2 - y1
    L = math.hypot(dx, dy) or 1.0
    ux, uy = dx / L, dy / L
    size = 8 + width*1.5
    bx, by = x2 - ux*size, y2 - uy*size
    px, py = -uy, ux
    p1 = QPointF(x2, y2)
    p2 = QPointF(bx + px*size*0.5, by + py*size*0.5)
    p3 = QPointF(bx - px*size*0.5, by - py*size*0.5)
    tri = QGraphicsPolygonItem(QPolygonF([p1, p2, p3]))
    tri.setBrush(QBrush(color)); tri.setPen(QPen(color))
    return line, tri

# ---------- Merkle viewer window ----------
class MerkleWindow(QMainWindow):
    HILITE_MS = 2200
    ZOOM_MIN = 0.25
    ZOOM_MAX = 5.0
    ZOOM_STEP = 1.2

    def __init__(self, mixer: ToyMixer):
        super().__init__()
        self.mixer = mixer
        self.setWindowTitle("Merkle Tree — live")
        self.view = QGraphicsView()
        self.scene = QGraphicsScene()
        self.view.setScene(self.scene)
        # White background (scene + view)
        self.scene.setBackgroundBrush(QBrush(QColor(255, 255, 255)))
        self.view.setBackgroundBrush(QBrush(QColor(255, 255, 255)))
        self.view.setStyleSheet("background: white;")
        # Zoom anchor
        self.view.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.view.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.zoom_level = 1.0
        self.setCentralWidget(self.view)
        self.resize(1100, 760)
        self.last_event = {"type": "init", "ts": datetime.now(timezone.utc), "new": set(), "spent": set(), "change": set(), "info": ""}

    def zoom_in(self):
        if self.zoom_level * self.ZOOM_STEP <= self.ZOOM_MAX:
            self.view.scale(self.ZOOM_STEP, self.ZOOM_STEP)
            self.zoom_level *= self.ZOOM_STEP

    def zoom_out(self):
        if self.zoom_level / self.ZOOM_STEP >= self.ZOOM_MIN:
            self.view.scale(1.0/self.ZOOM_STEP, 1.0/self.ZOOM_STEP)
            self.zoom_level /= self.ZOOM_STEP

    def note_deposit(self, ch: str):
        self.last_event = {"type":"deposit","ts":datetime.now(timezone.utc),"new":{ch},"spent":set(),"change":set(),"info":f"deposit {ch[:12]}…"}
    def note_withdraw(self, spent_hex: str, change_hexes: List[str]):
        self.last_event = {"type":"withdraw","ts":datetime.now(timezone.utc),"new":set(),"spent":{spent_hex},"change":set(change_hexes),"info":f"withdraw spent {spent_hex[:12]}…"}
    def note_send(self, info:str):
        self.last_event = {"type":"send","ts":datetime.now(timezone.utc),"new":set(),"spent":set(),"change":set(),"info":info}

    def _within_hilite(self) -> bool:
        return (datetime.now(timezone.utc) - self.last_event["ts"]).total_seconds()*1000 < self.HILITE_MS

    def render(self):
        self.scene.clear()
        layers = self.mixer.tree.layers
        root_hex = hexb(self.mixer.tree.root())
        title = f"Merkle root: {root_hex}"
        title_item = self.scene.addText(title)
        title_item.setDefaultTextColor(QColor(20,20,20))
        title_item.setPos(20, 10)

        if not layers:
            self.scene.addText("No leaves yet").setPos(20, 40)
            return

        H_MARGIN = 80; width = max(self.view.width()-40, 800)
        height = max(self.view.height()-60, 600)
        layer_count = len(layers)
        y_positions = [60 + i * ( (height-120) / max(1,layer_count-1) ) for i in range(layer_count)]
        index_to_commit = {idx: ch for ch, idx in self.mixer.commit_to_index.items()}

        # edges first
        for li in range(layer_count-1):
            cur_n = len(layers[li])
            for i in range(cur_n):
                parent = i//2
                x1 = H_MARGIN + i * ( (width-2*H_MARGIN) / max(1,cur_n-1) )
                y1 = y_positions[li]
                next_n = len(layers[li+1])
                x2 = H_MARGIN + parent * ( (width-2*H_MARGIN) / max(1,next_n-1) )
                y2 = y_positions[li+1]
                line = QGraphicsLineItem(x1,y1,x2,y2)
                line.setPen(QPen(QColor(0,0,0,80), 1.0))
                self.scene.addItem(line)

        new_set, change_set = set(), set()
        info = ""
        if self._within_hilite():
            ev = self.last_event; new_set = set(ev["new"]); change_set=set(ev["change"]); info = ev["info"]

        font = QFont("Consolas", 9)
        # nodes
        for li, layer in enumerate(layers):
            n = len(layer)
            for i, val in enumerate(layer):
                x = H_MARGIN + i * ( (width-2*H_MARGIN) / max(1,n-1) )
                y = y_positions[li]
                hexstr = hexb(val)
                if li == 0:
                    ch = index_to_commit.get(i, hexstr)
                    amt = self.mixer.commit_amount.get(ch, ZERO)
                    spent = ch in self.mixer.spent
                    r = 16
                    face = QColor(220, 242, 220); pen = QColor(60, 120, 60)
                    if ch in new_set: face = QColor(190, 250, 190); pen = QColor(30, 160, 30)
                    if ch in change_set: face = QColor(255, 230, 180); pen = QColor(220, 150, 50)
                    if spent: face = QColor(225,225,225); pen = QColor(120,120,120)
                    circ = QGraphicsEllipseItem(x-r, y-r, 2*r, 2*r)
                    circ.setBrush(QBrush(face)); circ.setPen(QPen(pen, 1.6))
                    self.scene.addItem(circ)
                    label = f"{ch[:12]}…\namt:{fmt2(amt)}" + ("  [SPENT]" if spent else "")
                    t = QGraphicsTextItem(label); t.setDefaultTextColor(QColor(20,20,20)); t.setFont(font)
                    t.setPos(x-52, y-34); self.scene.addItem(t)
                else:
                    w, h = 108, 28
                    rect = QGraphicsRectItem(x - w/2, y - h/2, w, h)
                    rect.setBrush(QBrush(QColor(225, 235, 255)))
                    rect.setPen(QPen(QColor(60,100,170), 1.2))
                    self.scene.addItem(rect)
                    t = QGraphicsTextItem(hexstr[:20]+"…"); t.setFont(QFont("Consolas", 9))
                    t.setDefaultTextColor(QColor(25,40,80)); t.setPos(x - w/2 + 4, y - h/2 + 4)
                    self.scene.addItem(t)

        leg = QGraphicsTextItem("Leaf colors: green=new, orange=change, gray=spent • Rectangles show subroot hashes")
        leg.setDefaultTextColor(QColor(30,30,30)); leg.setPos(20, self.view.height()-60); self.scene.addItem(leg)
        if info:
            banner = QGraphicsTextItem(info)
            banner.setDefaultTextColor(QColor(20,150,40))
            banner.setFont(QFont("Segoe UI", 10, QFont.Weight.Medium))
            banner.setPos(420, 12)
            self.scene.addItem(banner)

# ---------- Bubble graph view (two alternating rings) ----------
class GraphView(QGraphicsView):
    ZOOM_MIN = 0.25
    ZOOM_MAX = 5.0
    ZOOM_STEP = 1.2

    def __init__(self, mixer: ToyMixer, get_accounts_cb):
        super().__init__()
        self.mixer = mixer
        self.get_accounts = get_accounts_cb
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        self.recent_edges: List[Dict[str, Any]] = []
        self.max_edges = 60
        # zoom config
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.zoom_level = 1.0

    def set_recent_edges(self, edges: List[Dict[str, Any]]):
        self.recent_edges = edges[-self.max_edges:]

    def zoom_in(self):
        if self.zoom_level * self.ZOOM_STEP <= self.ZOOM_MAX:
            self.scale(self.ZOOM_STEP, self.ZOOM_STEP)
            self.zoom_level *= self.ZOOM_STEP

    def zoom_out(self):
        if self.zoom_level / self.ZOOM_STEP >= self.ZOOM_MIN:
            self.scale(1.0/self.ZOOM_STEP, 1.0/self.ZOOM_STEP)
            self.zoom_level /= self.ZOOM_STEP

    def redraw(self):
        self.scene.clear()
        W = max(self.width(), 800); H = max(self.height(), 600)
        cx, cy = W*0.45, H*0.45

        # mixer node (dark green)
        pool = float(self.mixer.pool_coins)
        mixer_r = 26 + 3*math.sqrt(pool + 1.0)
        mix_item = QGraphicsEllipseItem(cx-mixer_r, cy-mixer_r, mixer_r*2, mixer_r*2)
        mix_item.setBrush(QBrush(QColor(20, 100, 40)))   # dark green fill
        mix_item.setPen(QPen(QColor(10, 60, 25), 1.5))   # darker green border
        self.scene.addItem(mix_item)
        t = QGraphicsTextItem(f"MIXER\npool:{fmt2(self.mixer.pool_coins)}")
        t.setDefaultTextColor(QColor(255,255,255))
        t.setPos(cx-40, cy-22); self.scene.addItem(t)

        # gather & order accounts (stable, by alias)
        accs_all = list(self.get_accounts().values())
        accs = sorted(accs_all, key=lambda a: a["display"].lower())

        # split into two alternating rings
        inner_list, outer_list = [], []
        for i, info in enumerate(accs):
            (inner_list if i % 2 == 0 else outer_list).append(info)

        # radii
        base = min(W, H)
        r_inner = base * 0.28
        r_outer = base * 0.44
        node_pos: Dict[str, Tuple[float, float]] = {}

        # helper for drawing a node
        def draw_node(x, y, info):
            addr = info["addr"]; bal = self.mixer.balance_of(addr)
            r = 20 + 3*math.sqrt(float(bal) + 1.0)
            # colors
            if info.get("is_profit", False):
                fill, pen = QColor(170, 240, 170), QColor(90, 160, 90)   # light green profit
            elif info.get("is_shadow", False):
                fill, pen = QColor(200,60,60), QColor(120,30,30)
            else:
                fill, pen = QColor(40,110,180), QColor(20,60,110)
            circ = QGraphicsEllipseItem(x-r, y-r, 2*r, 2*r)
            circ.setBrush(QBrush(fill)); circ.setPen(QPen(pen, 1.5))
            self.scene.addItem(circ)
            tt = QGraphicsTextItem(f"{info['display']}\n{fmt2(bal)}")
            tt.setDefaultTextColor(QColor(255,255,255))
            tt.setPos(x-32, y-18); self.scene.addItem(tt)
            node_pos[addr] = (x, y)

        # place inner ring
        n_in = max(1, len(inner_list))
        for k, info in enumerate(inner_list):
            angle = 2*math.pi * k / n_in
            draw_node(cx + r_inner * math.cos(angle), cy + r_inner * math.sin(angle), info)

        # place outer ring with angular offset
        n_out = max(1, len(outer_list))
        offset = (math.pi / n_out) if n_out > 1 else 0.0
        for k, info in enumerate(outer_list):
            angle = 2*math.pi * k / n_out + offset
            draw_node(cx + r_outer * math.cos(angle), cy + r_outer * math.sin(angle), info)

        # arrows
        for tx in self.recent_edges:
            u, v, amt, typ = tx["from"], tx["to"], tx["amount"], tx["type"]
            x1, y1 = (cx, cy) if u == "mixer" else node_pos.get(u, (cx, cy))
            x2, y2 = (cx, cy) if v == "mixer" else node_pos.get(v, (cx, cy))
            color = QColor(50,90,200)  # default send
            if typ == "deposit": color = QColor(200,60,60)
            elif typ == "withdraw": color = QColor(60,170,70)
            elif typ == "fee": color = QColor(120, 210, 140)  # light green arrow for fee
            float_amt = float(q2(amt))
            width = 1.0 + math.log1p(max(1.0, float_amt))
            line, tri = arrow_item(x1, y1, x2, y2, color, width)
            self.scene.addItem(line); self.scene.addItem(tri)

# ---------- Main window ----------
class MainWindow(QMainWindow):
    def __init__(self, mixer: ToyMixer):
        super().__init__()
        self.mixer = mixer

        # datasets
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.alias_deposits: Dict[str, List[Dict[str, Any]]] = {}
        self.transfers: List[Dict[str, Any]] = []
        self.commitments_rows: List[Dict[str, Any]] = []
        self._last_account_order: List[str] = []  # keys in table order for delete-by-number

        # simulation state
        self.sim_active = False
        self.sim_has_session = False
        self.withdraw_phase_started = False
        self.sim_deposit_timer: Optional[QTimer] = None
        self.sim_withdraw_timer: Optional[QTimer] = None
        self.sim_warmup_timer: Optional[QTimer] = None
        self.sim_warmup_remaining_ms: int = 0
        self._sim_resume_at: Optional[datetime] = None
        self.sim_accounts: List[str] = []
        self.sim_params = {
            "num_addresses": 10,
            "initial_balance": D(100),
            "deposit_amounts": [D(1),D(5),D(10)],
            "withdraw_amounts": [D(1),D(5),D(10)],
            "deposit_interval_ms": 500,
            "withdraw_interval_ms": 500,
            "warmup_seconds": 15
        }

        # GUI
        self.setWindowTitle("Toy Mixer — PyQt6")
        self.resize(1450, 860)
        splitter = QSplitter()
        self.setCentralWidget(splitter)

        # left: graph
        self.graph = GraphView(self.mixer, self._get_accounts_dict)
        splitter.addWidget(self.graph)

        # right: panel
        right = QWidget(); splitter.addWidget(right)
        right.setMinimumWidth(600)
        rv = QVBoxLayout(right)

        # Accounts table
        self.lbl_accounts = QLabel("Accounts (live)")
        self.tbl_accounts = QTableView(); self.tbl_accounts.horizontalHeader().setStretchLastSection(True)
        self.tbl_accounts.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        rv.addWidget(self.lbl_accounts); rv.addWidget(self.tbl_accounts, 2)

        # Transfers table
        self.lbl_transfers = QLabel("Recent Transfers (live)")
        self.tbl_transfers = QTableView(); self.tbl_transfers.horizontalHeader().setStretchLastSection(True)
        rv.addWidget(self.lbl_transfers); rv.addWidget(self.tbl_transfers, 2)

        # Controls group
        controls = QGroupBox("Manual Controls")
        gl = QGridLayout(controls); gl.setHorizontalSpacing(8); gl.setVerticalSpacing(6)
        r = 0
        gl.addWidget(QLabel("New acct (alias, bal)"), r, 0)
        self.in_new = QLineEdit(); self.in_new.setPlaceholderText("Mallory")
        self.sb_new_bal = QDoubleSpinBox(); self.sb_new_bal.setRange(0.0, 1_000_000.0); self.sb_new_bal.setDecimals(2); self.sb_new_bal.setSingleStep(0.25); self.sb_new_bal.setValue(10.00)
        btn_new = QPushButton("Create/Set"); btn_new.clicked.connect(self.on_create)
        gl.addWidget(self.in_new, r, 1); gl.addWidget(self.sb_new_bal, r, 2); gl.addWidget(btn_new, r, 3); r += 1

        gl.addWidget(QLabel("Deposit (alias, amt)"), r, 0)
        self.in_dep_alias = QLineEdit(); self.in_dep_alias.setPlaceholderText("Alice")
        self.in_dep_amt = QLineEdit(); self.in_dep_amt.setPlaceholderText("3.00")
        btn_dep = QPushButton("Go"); btn_dep.clicked.connect(self.on_deposit)
        gl.addWidget(self.in_dep_alias, r, 1); gl.addWidget(self.in_dep_amt, r, 2); gl.addWidget(btn_dep, r, 3); r += 1

        gl.addWidget(QLabel("Withdraw (src→to, amt)"), r, 0)
        self.in_w_src = QLineEdit(); self.in_w_src.setPlaceholderText("Alice")
        self.in_w_to = QLineEdit(); self.in_w_to.setPlaceholderText("Alice_shadow")
        self.in_w_amt = QLineEdit(); self.in_w_amt.setPlaceholderText("2.00")
        btn_wd = QPushButton("Go"); btn_wd.clicked.connect(self.on_withdraw)
        gl.addWidget(self.in_w_src, r, 1); gl.addWidget(self.in_w_to, r, 2); gl.addWidget(self.in_w_amt, r, 3); gl.addWidget(btn_wd, r, 4); r += 1

        # Delete account by table row number (1-based)
        gl.addWidget(QLabel("Delete acct #"), r, 0)
        self.sb_del = QSpinBox(); self.sb_del.setRange(1, 1)
        btn_del = QPushButton("Delete"); btn_del.clicked.connect(self.on_delete_account)
        gl.addWidget(self.sb_del, r, 1); gl.addWidget(btn_del, r, 2); r += 1
        rv.addWidget(controls, 0)

        # View (zoom) group
        viewg = QGroupBox("View Controls (Zoom)")
        hv = QGridLayout(viewg)
        self.btn_graph_plus = QPushButton("Graph +"); self.btn_graph_plus.clicked.connect(lambda: self.graph.zoom_in())
        self.btn_graph_minus = QPushButton("Graph -"); self.btn_graph_minus.clicked.connect(lambda: self.graph.zoom_out())
        self.btn_merkle_plus = QPushButton("Merkle +")
        self.btn_merkle_minus = QPushButton("Merkle -")
        hv.addWidget(self.btn_graph_plus, 0, 0); hv.addWidget(self.btn_graph_minus, 0, 1)
        hv.addWidget(self.btn_merkle_plus, 1, 0); hv.addWidget(self.btn_merkle_minus, 1, 1)
        rv.addWidget(viewg, 0)

        # Simulation group
        sim = QGroupBox("Simulation")
        sg = QGridLayout(sim); sg.setHorizontalSpacing(8); sg.setVerticalSpacing(6)
        rr = 0
        sg.addWidget(QLabel("Num Addrs"), rr, 0); self.sb_num = QSpinBox(); self.sb_num.setRange(1, 200); self.sb_num.setValue(10); sg.addWidget(self.sb_num, rr, 1); rr += 1
        sg.addWidget(QLabel("Initial Balance"), rr, 0); self.sb_init = QDoubleSpinBox(); self.sb_init.setRange(0.0, 1_000_000.0); self.sb_init.setDecimals(2); self.sb_init.setSingleStep(1.0); self.sb_init.setValue(100.00); sg.addWidget(self.sb_init, rr, 1); rr += 1
        sg.addWidget(QLabel("Deposit Amnts (csv)"), rr, 0); self.in_dep_list = QLineEdit("1,5,10"); sg.addWidget(self.in_dep_list, rr, 1); rr += 1
        sg.addWidget(QLabel("Withdraw Amnts (csv)"), rr, 0); self.in_wd_list = QLineEdit("1,5,10"); sg.addWidget(self.in_wd_list, rr, 1); rr += 1
        sg.addWidget(QLabel("Deposit ms"), rr, 0); self.sb_dep_ms = QSpinBox(); self.sb_dep_ms.setRange(100, 60_000); self.sb_dep_ms.setValue(500); sg.addWidget(self.sb_dep_ms, rr, 1); rr += 1
        sg.addWidget(QLabel("Withdraw ms"), rr, 0); self.sb_wd_ms = QSpinBox(); self.sb_wd_ms.setRange(100, 60_000); self.sb_wd_ms.setValue(500); sg.addWidget(self.sb_wd_ms, rr, 1); rr += 1
        sg.addWidget(QLabel("Warmup sec"), rr, 0); self.sb_warm = QSpinBox(); self.sb_warm.setRange(0, 600); self.sb_warm.setValue(15); sg.addWidget(self.sb_warm, rr, 1); rr += 1
        # Commission (%)
        sg.addWidget(QLabel("Commission % (withdrawal)"), rr, 0)
        self.sb_commission = QDoubleSpinBox(); self.sb_commission.setRange(0.0, 100.0); self.sb_commission.setDecimals(2); self.sb_commission.setSingleStep(0.10); self.sb_commission.setValue(0.00)
        sg.addWidget(self.sb_commission, rr, 1); rr += 1

        self.btn_sim_start    = QPushButton("Start Simulation");    self.btn_sim_start.clicked.connect(self.sim_start)
        self.btn_sim_stop     = QPushButton("Stop Simulation");     self.btn_sim_stop.clicked.connect(self.sim_stop)
        self.btn_sim_continue = QPushButton("Continue Simulation"); self.btn_sim_continue.clicked.connect(self.sim_continue)
        self.btn_sim_end      = QPushButton("End Simulation");      self.btn_sim_end.clicked.connect(self.sim_end)

        sg.addWidget(self.btn_sim_start, rr, 0); sg.addWidget(self.btn_sim_stop, rr, 1); rr += 1
        sg.addWidget(self.btn_sim_continue, rr, 0); sg.addWidget(self.btn_sim_end, rr, 1); rr += 1
        rv.addWidget(sim, 0)

        # Merkle window (after buttons exist so we can wire +/-)
        self.merkle = MerkleWindow(self.mixer)
        self.btn_merkle_plus.clicked.connect(lambda: self.merkle.zoom_in())
        self.btn_merkle_minus.clicked.connect(lambda: self.merkle.zoom_out())
        self.merkle.show()

        # start condition
        self.reset_to_initial_state(write_csv=True)

        # UI refresh timer
        self.timer = QTimer(self); self.timer.setInterval(800)
        self.timer.timeout.connect(self.refresh_all)
        self.timer.start()

        self.refresh_all()
        self._ensure_csv_headers()

    # -------- CSV helpers --------
    def _ensure_csv_headers(self):
        if not os.path.exists(pjoin("accounts.csv")):
            with open(pjoin("accounts.csv"), "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(["alias","address","balance","created_at"])
        if not os.path.exists(pjoin("transfers.csv")):
            with open(pjoin("transfers.csv"), "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(["timestamp","from","to","amount","type"])
        if not os.path.exists(pjoin("commitments.csv")):
            with open(pjoin("commitments.csv"), "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(["timestamp","commitment","alias","amount","index","spent"])
        if not os.path.exists(pjoin("actions.csv")):
            with open(pjoin("actions.csv"), "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(["timestamp","action","details"])

    def _save_accounts_csv(self):
        with open(pjoin("accounts.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["alias","address","balance","created_at"])
            for key in self._last_account_order:
                info = self.accounts[key]
                w.writerow([info["display"], info["addr"], fmt2(self.mixer.balance_of(info["addr"])), info["created_at"].strftime("%H:%M:%S")])

    def _append_transfer_csv(self, row: Dict[str, Any]):
        with open(pjoin("transfers.csv"), "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([row["timestamp"], row["from"], row["to"], fmt2(row["amount"]), row["type"]])

    def _save_commitments_csv(self):
        with open(pjoin("commitments.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp","commitment","alias","amount","index","spent"])
            for r in self.commitments_rows:
                w.writerow([r["timestamp"], r["commitment"], r["alias"], fmt2(r["amount"]), r["index"], r["spent"]])

    def _append_action_csv(self, action: str, details: str):
        with open(pjoin("actions.csv"), "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([utc_now_str(), action, details])

    def _reset_csvs_to_start(self):
        with open(pjoin("transfers.csv"), "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["timestamp","from","to","amount","type"])
        with open(pjoin("commitments.csv"), "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["timestamp","commitment","alias","amount","index","spent"])

    # -------- Accounts/data --------
    def _get_accounts_dict(self): return self.accounts

    def _create_account(self, alias_raw: str, *, is_shadow: bool=False,
                        is_profit: bool=False,
                        initial_balance: Optional[Decimal]=None, set_if_exists: bool=False) -> str:
        """Create or ensure alias exists; can mark as shadow/profit. Optional set balance (Decimal)."""
        alias = alias_raw.strip()
        if not alias: return ""
        key = alias.lower()
        if key in self.accounts:
            if is_shadow: self.accounts[key]["is_shadow"] = True
            if is_profit: self.accounts[key]["is_profit"] = True
            addr = self.accounts[key]["addr"]
            if initial_balance is not None and set_if_exists:
                self.mixer.ledger[addr] = q2(initial_balance)
                logger.info("Set balance for %s to %s", alias, fmt2(initial_balance))
                self._append_action_csv("set_balance", f"{alias} -> {fmt2(initial_balance)}")
            return addr

        addr = f"addr_{key}_{os.urandom(3).hex()}"
        self.accounts[key] = {
            "display": alias, "addr": addr, "created_at": datetime.now(timezone.utc),
            "is_shadow": bool(is_shadow), "is_profit": bool(is_profit)
        }
        self.mixer.ledger.setdefault(addr, ZERO)
        if initial_balance is not None:
            self.mixer.ledger[addr] = q2(initial_balance)
        self.alias_deposits.setdefault(key, [])
        logger.info(f"Account created: {alias} -> {addr}{' (shadow)' if is_shadow else ''}{' (profit)' if is_profit else ''}, bal={fmt2(self.mixer.ledger[addr])}")
        self._append_action_csv("create_account", f"{alias} -> {addr}, bal={fmt2(self.mixer.ledger[addr])}{' (shadow)' if is_shadow else ''}{' (profit)' if is_profit else ''}")
        return addr

    def _record_commit_row(self, ch: str, alias: str, amt: Decimal):
        self.commitments_rows.append({
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "commitment": ch, "alias": alias, "amount": q2(amt),
            "index": self.mixer.commit_to_index[ch], "spent": False
        })
        self._save_commitments_csv()

    # -------- Manual UI Callbacks --------
    def on_create(self):
        alias = (self.in_new.text() or "").strip()
        if not alias: return
        bal = q2(self.sb_new_bal.value())
        # Profit guard
        is_profit = (alias.strip().lower() == "profit")
        self._create_account(alias, initial_balance=bal, set_if_exists=True, is_profit=is_profit)
        self.refresh_all()

    def on_deposit(self):
        alias = (self.in_dep_alias.text() or "").strip()
        amt_s = (self.in_dep_amt.text() or "").strip()
        if not alias or not amt_s: return
        try: amt = q2(Decimal(amt_s))
        except Exception: return
        self._op_deposit(alias, amt)

    def on_withdraw(self):
        src = (self.in_w_src.text() or "").strip()
        to = (self.in_w_to.text() or "").strip()
        amt_s = (self.in_w_amt.text() or "").strip()
        if not src or not to or not amt_s: return
        try: amt = q2(Decimal(amt_s))
        except Exception: return
        self._op_withdraw(src, to, amt)

    def on_delete_account(self):
        # delete by row number as shown in Accounts table (1-based)
        idx = int(self.sb_del.value()) - 1
        if idx < 0 or idx >= len(self._last_account_order):
            return
        key = self._last_account_order[idx]
        if key == "profit":
            logger.warning("Refusing to delete 'Profit' account")
            self._append_action_csv("delete_refused", "Profit cannot be deleted")
            return
        unspent = any(not d["spent"] for d in self.alias_deposits.get(key, []))
        if unspent:
            logger.warning("Refusing to delete '%s': unspent deposits exist", self.accounts[key]["display"])
            self._append_action_csv("delete_refused", f"{self.accounts[key]['display']} has unspent deposits")
            return
        info = self.accounts[key]; addr = info["addr"]
        self.accounts.pop(key, None); self.alias_deposits.pop(key, None)
        if addr in self.mixer.ledger: self.mixer.ledger.pop(addr, None)
        self._append_action_csv("delete_account", f"{info['display']} ({addr})")
        logger.info("Deleted account %s", info["display"])
        self.refresh_all()

    # -------- Core ops --------
    def _op_deposit(self, alias_raw: str, amount: Decimal):
        key = alias_raw.lower()
        if key not in self.accounts:
            logger.warning("Deposit: unknown alias %s", alias_raw); return
        addr = self.accounts[key]["addr"]
        amount = q2(amount)
        if amount <= ZERO: return
        try:
            sec = make_secret()
            ch = self.mixer.deposit(sec, addr, amount)
        except Exception:
            logger.exception("deposit exception")
            return
        rec = {"secret": sec, "commit": ch, "amount": amount, "spent": False}
        self.alias_deposits[key].append(rec)
        self._record_commit_row(ch, alias_raw, amount)
        tx = {"timestamp": utc_now_str(), "from": addr, "to": "mixer", "amount": amount, "type": "deposit"}
        self.transfers.append(tx); self._append_transfer_csv(tx)
        self._append_action_csv("deposit", f"{alias_raw} -> MIXER amount={fmt2(amount)} commit={ch}")
        self.merkle.note_deposit(ch)
        self.refresh_all()

    def _op_withdraw(self, src_alias: str, to_alias: str, amount: Decimal):
        src_key = src_alias.lower()
        if src_key not in self.accounts:
            logger.warning("Withdraw: unknown src %s", src_alias); return
        to_addr = self._create_account(to_alias, is_shadow=True)
        amount = q2(amount)
        if amount <= ZERO: return
        deposits = [d for d in self.alias_deposits.get(src_key, []) if not d["spent"]]
        total = q2(sum(q2(d["amount"]) for d in deposits))
        if total < amount: return

        profit_addr = self._create_account("Profit", is_profit=True)
        pct = float(self.sb_commission.value())

        remaining = amount
        spent_for_event: Optional[str] = None
        change_hexes: List[str] = []
        while remaining > ZERO and deposits:
            d = deposits.pop(0)
            if d["spent"]: continue
            take = q2(min(remaining, q2(d["amount"])))
            withdrawn, spent_hex, change_list, fee, net = self.mixer.withdraw(
                d["secret"], to_addr, take, commission_percent=pct, profit_addr=profit_addr
            )
            if withdrawn <= ZERO: return
            d["spent"] = True
            remaining = q2(remaining - withdrawn)
            # mark spent commit
            for row in reversed(self.commitments_rows):
                if row["commitment"] == spent_hex:
                    row["spent"] = True; break
            # add any change notes (belong to src alias)
            for (chg_hex, chg_amt, chg_sec) in change_list:
                self.alias_deposits[src_key].append({"secret": chg_sec, "commit": chg_hex, "amount": q2(chg_amt), "spent": False})
                self._record_commit_row(chg_hex, src_alias, q2(chg_amt))
                change_hexes.append(chg_hex)
            # transfers: net to recipient + fee to Profit
            tx1 = {"timestamp": utc_now_str(), "from": "mixer", "to": to_addr, "amount": net, "type": "withdraw"}
            self.transfers.append(tx1); self._append_transfer_csv(tx1)
            if fee > ZERO:
                tx2 = {"timestamp": utc_now_str(), "from": "mixer", "to": profit_addr, "amount": fee, "type": "fee"}
                self.transfers.append(tx2); self._append_transfer_csv(tx2)
            spent_for_event = spent_hex

        self._save_commitments_csv()
        self._append_action_csv("withdraw", f"{src_alias} -> {to_alias} gross={fmt2(amount)} pct={pct:.2f}% spent={spent_for_event} changes={len(change_hexes)}")
        if spent_for_event: self.merkle.note_withdraw(spent_for_event, change_hexes)
        self.refresh_all()

    # -------- Simulation controls --------
    def _parse_amounts(self, s: str) -> List[Decimal]:
        try:
            vals = [q2(Decimal(x.strip())) for x in s.split(",") if x.strip()]
            return [v for v in vals if v > ZERO]
        except Exception:
            return [D(1),D(5),D(10)]

    def sim_start(self):
        # pull params
        self.sim_params["num_addresses"] = int(self.sb_num.value())
        self.sim_params["initial_balance"] = q2(self.sb_init.value())
        self.sim_params["deposit_amounts"] = self._parse_amounts(self.in_dep_list.text())
        self.sim_params["withdraw_amounts"] = self._parse_amounts(self.in_wd_list.text())
        self.sim_params["deposit_interval_ms"] = int(self.sb_dep_ms.value())
        self.sim_params["withdraw_interval_ms"] = int(self.sb_wd_ms.value())
        self.sim_params["warmup_seconds"] = int(self.sb_warm.value())

        # prepare sim accounts
        base_names = ["Alice","Bob","Carol","Dave","Eve","Frank","Grace","Heidi","Ivan","Judy"]
        n = self.sim_params["num_addresses"]
        if n > len(base_names):
            base_names += [f"Sim{i:02d}" for i in range(len(base_names)+1, n+1)]
        else:
            base_names = base_names[:n]

        self.sim_accounts = []
        init_bal = q2(self.sim_params["initial_balance"])

        # reset everything
        self.accounts.clear(); self.alias_deposits.clear(); self.transfers.clear(); self.commitments_rows.clear()
        self.mixer = ToyMixer()
        self.graph.mixer = self.mixer
        self.merkle.mixer = self.mixer

        # create Profit first
        self._create_account("Profit", is_profit=True, initial_balance=ZERO)

        # then user accounts
        for name in base_names:
            self._create_account(name, is_shadow=False, initial_balance=init_bal)
            self.sim_accounts.append(name)

        # warmup & timers
        self.sim_warmup_remaining_ms = self.sim_params["warmup_seconds"] * 1000
        self.withdraw_phase_started = False
        self._sim_resume_at = datetime.now(timezone.utc)

        self.sim_has_session = True
        self.sim_active = True

        self._append_action_csv("sim_start", f"N={n}, init={fmt2(init_bal)}, dep_ms={self.sim_params['deposit_interval_ms']}, wd_ms={self.sim_params['withdraw_interval_ms']}, warmup={self.sim_params['warmup_seconds']}, commission={self.sb_commission.value():.2f}%")
        logger.info("Simulation started with %d accounts, init=%s, commission=%.2f%%", n, fmt2(init_bal), self.sb_commission.value())

        # timers
        if self.sim_deposit_timer: self.sim_deposit_timer.stop()
        if self.sim_withdraw_timer: self.sim_withdraw_timer.stop()
        if self.sim_warmup_timer: self.sim_warmup_timer.stop()

        self.sim_deposit_timer = QTimer(self); self.sim_deposit_timer.setInterval(self.sim_params["deposit_interval_ms"])
        self.sim_deposit_timer.timeout.connect(self._sim_tick_deposit); self.sim_deposit_timer.start()

        self.sim_warmup_timer = QTimer(self); self.sim_warmup_timer.setSingleShot(True)
        self.sim_warmup_timer.timeout.connect(self._sim_begin_withdraws)
        self.sim_warmup_timer.start(self.sim_warmup_remaining_ms)

        self.refresh_all()

    def _sim_begin_withdraws(self):
        if self.withdraw_phase_started: return
        self.withdraw_phase_started = True
        self._append_action_csv("sim_phase", "begin_withdraws")
        logger.info("Simulation entering withdraw phase")
        self.sim_withdraw_timer = QTimer(self); self.sim_withdraw_timer.setInterval(self.sim_params["withdraw_interval_ms"])
        self.sim_withdraw_timer.timeout.connect(self._sim_tick_withdraw); self.sim_withdraw_timer.start()

    def sim_stop(self):
        if self.sim_deposit_timer: self.sim_deposit_timer.stop()
        if self.sim_withdraw_timer: self.sim_withdraw_timer.stop()
        if self.sim_warmup_timer: self.sim_warmup_timer.stop()

        if self.sim_has_session and not self.withdraw_phase_started and self._sim_resume_at:
            now = datetime.now(timezone.utc)
            elapsed_ms = int((now - self._sim_resume_at).total_seconds() * 1000)
            self.sim_warmup_remaining_ms = max(0, self.sim_warmup_remaining_ms - elapsed_ms)

        self.sim_active = False
        self._append_action_csv("sim_stop", f"paused; warmup_remaining_ms={self.sim_warmup_remaining_ms}, withdraw_started={self.withdraw_phase_started}")
        logger.info("Simulation stopped (paused)")

    def sim_continue(self):
        if not self.sim_has_session:
            logger.warning("Continue requested but no active session exists")
            self._append_action_csv("sim_continue_refused", "no session")
            return
        if self.sim_active:
            logger.info("Continue ignored; already active")
            return

        self._sim_resume_at = datetime.now(timezone.utc)
        if self.sim_deposit_timer is None:
            self.sim_deposit_timer = QTimer(self); 
            self.sim_deposit_timer.timeout.connect(self._sim_tick_deposit)
        self.sim_deposit_timer.setInterval(self.sim_params["deposit_interval_ms"])
        self.sim_deposit_timer.start()

        if not self.withdraw_phase_started:
            if self.sim_warmup_remaining_ms <= 0:
                self._sim_begin_withdraws()
            else:
                self.sim_warmup_timer = QTimer(self); self.sim_warmup_timer.setSingleShot(True)
                self.sim_warmup_timer.timeout.connect(self._sim_begin_withdraws)
                self.sim_warmup_timer.start(self.sim_warmup_remaining_ms)
        else:
            if self.sim_withdraw_timer is None:
                self.sim_withdraw_timer = QTimer(self); 
                self.sim_withdraw_timer.timeout.connect(self._sim_tick_withdraw)
            self.sim_withdraw_timer.setInterval(self.sim_params["withdraw_interval_ms"])
            self.sim_withdraw_timer.start()

        self.sim_active = True
        self._append_action_csv("sim_continue", f"resumed; warmup_remaining_ms={self.sim_warmup_remaining_ms}, withdraw_started={self.withdraw_phase_started}")
        logger.info("Simulation continued")

    def sim_end(self):
        self.sim_stop()
        self.sim_active = False
        self.sim_has_session = False
        self.withdraw_phase_started = False
        self.sim_warmup_remaining_ms = 0
        self._append_action_csv("sim_end", "ended")
        logger.info("Simulation ended")
        self.reset_to_initial_state(write_csv=True)

    # -------- Simulation tick helpers --------
    def _sim_pick(self, amounts: List[Decimal]) -> Decimal:
        return random.choice(amounts) if amounts else D(1)

    def _sim_tick_deposit(self):
        if not self.sim_active or not self.sim_accounts: return
        alias = random.choice(self.sim_accounts)
        amt = q2(self._sim_pick(self.sim_params["deposit_amounts"]))
        addr = self.accounts[alias.lower()]["addr"]
        if self.mixer.balance_of(addr) >= amt:
            self._op_deposit(alias, amt)

    def _sim_tick_withdraw(self):
        if not self.sim_active or not self.sim_accounts: return
        base = random.choice(self.sim_accounts)
        amt = q2(self._sim_pick(self.sim_params["withdraw_amounts"]))
        shadow = f"{base}_shadow"
        self._op_withdraw(base, shadow, amt)

    # -------- Reset to script start condition --------
    def reset_to_initial_state(self, *, write_csv: bool):
        # fresh mixer + clear datasets
        self.accounts.clear(); self.alias_deposits.clear(); self.transfers.clear(); self.commitments_rows.clear()
        self.mixer = ToyMixer()
        self.graph.mixer = self.mixer
        self.merkle.mixer = self.mixer
        self.merkle.last_event = {"type": "init", "ts": datetime.now(timezone.utc), "new": set(), "spent": set(), "change": set(), "info": ""}

        # Profit account first
        self._create_account("Profit", is_profit=True, initial_balance=ZERO)

        # only Alice, Bob, Carol with 10 each
        for name in ["Alice","Bob","Carol"]:
            self._create_account(name, initial_balance=D(10))

        if write_csv:
            self._reset_csvs_to_start()
            self.refresh_all()  # rebuild order before writing accounts.csv
            self._save_accounts_csv()
            self._append_action_csv("sim_reset", "state reset to Profit + Alice/Bob/Carol with 10.00 each")

        self.refresh_all()

    # -------- helpers --------
    def _addr_of(self, alias: str) -> str:
        info = self.accounts.get(alias.lower()); return "" if not info else info["addr"]

    # -------- refresh everything --------
    def refresh_all(self):
        try:
            # accounts table
            headers = ["alias","address","balance","created_at"]
            rows = []
            ordered = sorted(self.accounts.items(), key=lambda kv: (kv[1]["display"].lower()))
            self._last_account_order = [k for k, _ in ordered]
            for key, info in ordered:
                rows.append([info["display"], info["addr"], fmt2(self.mixer.balance_of(info["addr"])), info["created_at"].strftime("%H:%M:%S")])
            self.tbl_accounts.setModel(SimpleTableModel(headers, rows))
            self.sb_del.setMaximum(max(1, len(self._last_account_order)))
            if rows:
                self.tbl_accounts.setColumnWidth(0, 150)
                self.tbl_accounts.setColumnWidth(1, 360)
                self.tbl_accounts.setColumnWidth(2, 90)
                self.tbl_accounts.setColumnWidth(3, 100)
            if os.path.exists(pjoin("accounts.csv")):
                self._save_accounts_csv()

            # transfers table (last 20)
            headers2 = ["timestamp","from","to","amount","type"]
            last = self.transfers[-20:]
            rows2 = [[r["timestamp"], r["from"], r["to"], fmt2(r["amount"]), r["type"]] for r in last]
            self.tbl_transfers.setModel(SimpleTableModel(headers2, rows2))
            if rows2:
                self.tbl_transfers.setColumnWidth(0, 140)
                self.tbl_transfers.setColumnWidth(1, 255)
                self.tbl_transfers.setColumnWidth(2, 255)
                self.tbl_transfers.setColumnWidth(3, 80)
                self.tbl_transfers.setColumnWidth(4, 80)

            # graph & merkle
            self.graph.set_recent_edges(self.transfers)
            self.graph.redraw()
            self.merkle.render()
        except Exception as e:
            logger.error("refresh failed: %s\n%s", e, traceback.format_exc())

# ============================ run ============================
def main():
    import sys
    app = QApplication(sys.argv)
    mixer = ToyMixer()
    w = MainWindow(mixer)
    w.show()
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())
