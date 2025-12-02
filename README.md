# Toy Mixer Simulator
<img width="1978" height="1170" alt="image" src="https://github.com/user-attachments/assets/cfaa121b-da0f-4c14-bf56-a10cbe860f5c" />

Educational Ethereum-style mixer simulator with a PyQt6 GUI, live bubble graph and Merkle tree visualizations. It supports manual deposits and withdrawals, a configurable traffic simulation, Tornado Cash–style withdrawal fees routed to a **Profit** address, plus CSV logging of all activity.

> ⚠️ **Educational only**
>
> This project is a local proof‑of‑concept. It does **not** connect to any blockchain, does **not** move real funds, and is intended only for learning about mixer designs and privacy concepts.

---

## Features

* **PyQt6 GUI**

  * Bubble graph view of all accounts and the mixer.
  * Two alternating rings of account bubbles around a central mixer bubble.
  * Mixer bubble in dark green; shadow accounts in red; Profit account in light green.
  * Zoom controls (+/−) for both the graph and Merkle tree views.
* **Merkle Tree visualization**

  * Live Merkle tree view in a separate window with a white background.
  * Shows leaves (commitments) and internal “subroot” hashes.
  * Highlights newly added, spent, and change commitments.
* **Mixer core**

  * Deposits create SHA‑256 commitments stored in a Merkle tree.
  * Withdrawals verify Merkle inclusion proofs.
  * Balances and amounts tracked with **two decimal places** using `Decimal`.
* **Tornado‑style commission**

  * Adjustable fee percentage applied on **withdrawal**.
  * Fee is computed with decimals (works correctly even for tiny amounts, e.g. 1% of 1.00 = 0.01).
  * All fees are routed to a dedicated **Profit** account.
* **Simulation engine**

  * Start / Stop / Continue / End a pseudo‑random traffic simulation.
  * Creates N accounts with an initial balance and automatically:

    * deposits random amounts into the mixer,
    * then withdraws to new “shadow” addresses (e.g. `Alice_shadow`).
  * All simulation parameters are adjustable (counts, intervals, amounts, warmup time, commission).
* **Manual controls**

  * Create / update an account with a chosen starting balance.
  * Deposit from an account to the mixer (with amount).
  * Withdraw from an account’s commitments to a target alias (with amount).
  * Delete an account by its row number (if it has no unspent deposits).
* **Data logging**

  * Live tables for accounts and recent transfers.
  * CSV files for accounts, transfers, commitments, and actions.
  * Rotating log file (`mixer.log`) for debugging.

---

## Requirements

* Python 3.10+ (tested with recent 3.x)
* PyQt6

Install dependencies (example):

```bash
pip install pyqt6
```

If you have a `requirements.txt`, you can also do:

```bash
pip install -r requirements.txt
```

---

## Running the app

1. Clone the repository:

```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

2. Run the main script:

```bash
python main.py
```

Two windows should appear:

* **Main window** (graph + control panel + data tables)
* **Merkle Tree window** (live tree visualization)

---

## UI Overview

### Bubble graph view

* Central **MIXER** node in dark green.
* Account nodes arranged on two alternating rings around the mixer.
* **Colors**:

  * Normal accounts: blue.
  * Shadow accounts: red.
  * Profit account: light green.
* **Arrows**:

  * Red arrows: deposits (account → mixer).
  * Green arrows: withdrawals (mixer → account).
  * Light‑green arrows: fees (mixer → Profit).

Use the **Graph +** and **Graph −** buttons to zoom in and out.

### Merkle Tree window

* Shows the current Merkle tree for all commitments.
* Bottom layer: leaves (commitments) with amounts and spent status.
* Upper layers: rectangles for subroot hashes.
* Recent operations (deposits / withdrawals) are highlighted briefly.

Use the **Merkle +** and **Merkle −** buttons in the main window to zoom.

---

## Manual Controls

Found under **“Manual Controls”** in the right‑hand panel.

### Create / Set account

* Fields: `New acct (alias, bal)`.
* Enter an alias (e.g. `Alice`) and a starting balance (supports decimals, e.g. `10.50`).
* Click **Create/Set**:

  * If the alias does not exist, a new account is created.
  * If it exists, its balance is updated.
  * The alias `Profit` is treated specially as the fee sink.

### Deposit

* Fields: `Deposit (alias, amt)`.
* Enter the account alias and the deposit amount.
* On success:

  * The account balance decreases.
  * The mixer’s pool increases.
  * A new commitment is added to the Merkle tree.
  * A deposit transfer is recorded and visualized.

### Withdraw

* Fields: `Withdraw (src→to, amt)`.
* `src` is the alias whose deposits will be spent.
* `to` is the alias receiving the withdrawn (mixed) funds.
* `amt` is the gross withdrawal amount.
* On success:

  * The mixer’s pool decreases by the gross amount.
  * A **commission** is computed and sent to the `Profit` account.
  * The remaining net amount is credited to the recipient.
  * Commitments for the source alias are marked spent; change notes are created if needed.

### Delete account

* Choose a row number from the **Accounts** table.
* Enter the number in **Delete acct #** and press **Delete**.
* The account can only be deleted if it has **no unspent deposits**.
* The `Profit` account cannot be deleted.

---

## Simulation Controls

Found under **“Simulation”**.

Parameters:

* **Num Addrs** – how many accounts to create for the simulation.
* **Initial Balance** – starting balance per simulated account.
* **Deposit Amnts (csv)** – list of deposit sizes (e.g. `1,5,10`).
* **Withdraw Amnts (csv)** – list of withdrawal sizes.
* **Deposit ms** – interval between automatic deposits in milliseconds.
* **Withdraw ms** – interval between automatic withdrawals.
* **Warmup sec** – how long to run only deposits before withdrawals begin.
* **Commission % (withdrawal)** – fee percentage applied on each withdrawal.

Buttons:

* **Start Simulation** – resets the mixer, creates simulation accounts plus a Profit account, and begins automatic deposits.
* **Stop Simulation** – pauses all simulation timers.
* **Continue Simulation** – resumes a paused simulation (including any remaining warmup time).
* **End Simulation** – stops the simulation and resets the state back to the default (only Profit + Alice, Bob, Carol).

During simulation, each non‑shadow account periodically:

* deposits a random allowed amount into the mixer, then
* later withdraws random amounts to a corresponding `alias_shadow` account.

---

## Logged Data & Files

All files are created in the same directory as `main.py`:

* **`mixer.log`** – rotating log with timestamps and detailed debug messages.
* **`accounts.csv`** – current accounts, addresses, and balances.
* **`transfers.csv`** – chronological record of deposits, withdrawals, and fee transfers.
* **`commitments.csv`** – all commitments with alias, amount, index, and spent flag.
* **`actions.csv`** – high‑level user and simulation actions (start, stop, withdraw, etc.).

These files make it easy to analyze the mixer’s behavior offline or feed the data into external visualization tools.

---

## Safety Notes

* This is **not** a production mixer.
* No blockchain or real assets are involved.
* Use this purely for learning about commitments, Merkle trees, and transaction flows.

---
