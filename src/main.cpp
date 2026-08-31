// SPDX-License-Identifier: MIT
// cpp-xfrm-watch — XFRM (IPsec) Linux kernel statistics monitor (/proc/net/xfrm_stat)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o xfrm-watch
// Usage: ./xfrm-watch [--dir in|out|fwd|acq] [--key PREFIX] [--nonzero] [--top N]
//                     [--watch N] [--json] [--demo] [--file PATH]
//                     [--no-color] [--selftest]

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET   = "\x1b[0m";
static std::string C_BOLD    = "\x1b[1m";
static std::string C_DIM     = "\x1b[2m";
static std::string C_RED     = "\x1b[31m";
static std::string C_GREEN   = "\x1b[32m";
static std::string C_YELLOW  = "\x1b[33m";
static std::string C_BLUE    = "\x1b[34m";
static std::string C_CYAN    = "\x1b[36m";
static std::string C_MAGENTA = "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

// ─────────────────────────────────────────────────────────────────────────────
// Model — one XFRM counter (net/xfrm/xfrm_proc.c, xfrm_statistics_seq_show)
// ─────────────────────────────────────────────────────────────────────────────
enum class Dir { In, Out, Fwd, Acq, Unknown };

static Dir dir_of(std::string_view name) {
  if (name.starts_with("XfrmIn"))  return Dir::In;
  if (name.starts_with("XfrmOut")) return Dir::Out;
  if (name.starts_with("XfrmFwd")) return Dir::Fwd;
  if (name.starts_with("XfrmAcq")) return Dir::Acq;
  return Dir::Unknown;
}

static const char* dir_name(Dir d) {
  switch (d) {
    case Dir::In:  return "in";
    case Dir::Out: return "out";
    case Dir::Fwd: return "fwd";
    case Dir::Acq: return "acq";
    default:       return "?";
  }
}

struct Counter {
  std::string name;
  unsigned long long value = 0;

  Dir dir() const { return dir_of(name); }
  bool nonzero() const { return value != 0; }
};

struct Snapshot {
  long long ts = 0;
  std::vector<Counter> counters;

  // Lookup by exact name (used by watch-mode deltas and selftest)
  const Counter* find(std::string_view name) const {
    auto it = std::find_if(counters.begin(), counters.end(),
                           [name](const Counter& c) { return c.name == name; });
    return it == counters.end() ? nullptr : &*it;
  }

  unsigned long long dir_total(Dir d) const {
    unsigned long long t = 0;
    for (const auto& c : counters)
      if (c.dir() == d) t += c.value;
    return t;
  }

  unsigned long long total() const {
    unsigned long long t = 0;
    for (const auto& c : counters) t += c.value;
    return t;
  }

  std::size_t nonzero_count() const {
    return static_cast<std::size_t>(
      std::count_if(counters.begin(), counters.end(),
                    [](const Counter& c) { return c.nonzero(); }));
  }
};

// Well-known semantic tags for the most informative counters
struct Tag {
  const char* name;
  const char* tag;
};
static const Tag kTags[] = {
  {"XfrmInNoStates",         "state-lookup"},   // no SA matched inbound packet
  {"XfrmInNoPols",           "policy-lookup"},  // no policy matched inbound packet
  {"XfrmInPolBlock",         "policy-block"},   // inbound blocked by policy
  {"XfrmInStateExpired",     "expired"},        // SA lifetime expired on receive
  {"XfrmInStateSeqError",    "replay"},         // anti-replay check failed
  {"XfrmOutNoStates",        "state-lookup"},   // unable to find SA to encrypt
  {"XfrmOutPolBlock",        "policy-block"},   // outbound blocked by policy
  {"XfrmOutPolDead",         "policy-block"},   // policy marked dead
  {"XfrmAcquireError",       "acquire"},
};

static const char* tag_of(std::string_view name) {
  for (const auto& t : kTags)
    if (name == t.name) return t.tag;
  return nullptr;
}

// ─────────────────────────────────────────────────────────────────────────────
// Loaders
// ─────────────────────────────────────────────────────────────────────────────
static unsigned long long parse_u64(std::string_view s) {
  unsigned long long v = 0;
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return 0;
  s.remove_prefix(start);
  std::from_chars(s.data(), s.data() + s.size(), v);
  return v;
}

// Format: "XfrmInError    \t0" — name, run of spaces/tabs, decimal value, \n.
// Tolerates blank lines and '#' comments (--file dumps).
static bool load_snapshot(Snapshot& snap, const std::string& path) {
  std::ifstream f(path);
  if (!f) return false;
  std::string line;
  snap.counters.clear();
  while (std::getline(f, line)) {
    if (line.empty()) continue;
    size_t c = line.find_first_of('#');
    if (c != std::string::npos) line = line.substr(0, c);
    // trim trailing whitespace
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
      line.pop_back();
    if (line.empty()) continue;

    size_t tab = line.find('\t');
    size_t sp = line.find("  ");
    size_t sep = std::string::npos;
    if (tab != std::string::npos) sep = tab;
    else if (sp != std::string::npos) sep = sp;
    if (sep == std::string::npos) continue;  // malformed row — skip

    Counter ctr;
    ctr.name = line.substr(0, sep);
    // trim BOTH ends of the name (leading spaces appear in hand-edited dumps)
    auto nb = ctr.name.find_first_not_of(" \t");
    if (nb == std::string::npos) continue;
    ctr.name = ctr.name.substr(nb);
    while (!ctr.name.empty() && (ctr.name.back() == ' ' || ctr.name.back() == '\t'))
      ctr.name.pop_back();
    ctr.value = parse_u64(std::string_view(line).substr(sep));
    snap.counters.push_back(std::move(ctr));
  }
  return !snap.counters.empty();
}

// Synthetic busy VPN gateway: nonzero counters with a realistic error profile.
static bool demo_load(Snapshot& snap) {
  struct { const char* n; unsigned long long v; } rows[] = {
    {"XfrmInError", 12ull}, {"XfrmInBufferError", 0}, {"XfrmInHdrError", 3},
    {"XfrmInNoStates", 4217ull}, {"XfrmInStateProtoError", 2},
    {"XfrmInStateModeError", 0}, {"XfrmInStateSeqError", 187ull},
    {"XfrmInStateExpired", 54ull}, {"XfrmInStateMismatch", 9},
    {"XfrmInStateInvalid", 0}, {"XfrmInTmplMismatch", 6},
    {"XfrmInNoPols", 1340ull}, {"XfrmInPolBlock", 7}, {"XfrmInPolError", 1},
    {"XfrmOutError", 4}, {"XfrmOutBundleGenError", 2},
    {"XfrmOutBundleCheckError", 0}, {"XfrmOutNoStates", 689ull},
    {"XfrmOutStateProtoError", 1}, {"XfrmOutStateModeError", 0},
    {"XfrmOutStateSeqError", 0}, {"XfrmOutStateExpired", 23},
    {"XfrmOutPolBlock", 3}, {"XfrmOutPolDead", 0}, {"XfrmOutPolError", 0},
    {"XfrmFwdHdrError", 5}, {"XfrmOutStateInvalid", 0}, {"XfrmAcquireError", 16},
  };
  snap.counters.clear();
  for (const auto& r : rows) snap.counters.push_back(Counter{r.n, r.v});
  return !snap.counters.empty();
}

// ─────────────────────────────────────────────────────────────────────────────
// Renderers
// ─────────────────────────────────────────────────────────────────────────────
struct Filters {
  std::string dir;          // in|out|fwd|acq
  std::string key;          // name prefix
  bool nonzero = false;
  int top = 0;              // 0 = all
};

static bool passes(const Counter& c, const Filters& f) {
  if (f.nonzero && !c.nonzero()) return false;
  if (!f.dir.empty() && dir_name(c.dir()) != f.dir) return false;
  if (!f.key.empty() && !c.name.starts_with(f.key)) return false;
  return true;
}

static void render_snapshot(const Snapshot& snap, const Filters& f, bool quiet_header) {
  if (!quiet_header) {
    std::println(std::cout, "{}-- XFRM (IPsec) kernel counters  /proc/net/xfrm_stat --{}", C_BOLD, C_RESET);
    std::println(std::cout, "{}total {}  in {}  out {}  fwd {}  acq {}  nonzero {}{}",
                 C_DIM,
                 snap.total(), snap.dir_total(Dir::In), snap.dir_total(Dir::Out),
                 snap.dir_total(Dir::Fwd), snap.dir_total(Dir::Acq),
                 snap.nonzero_count(), C_RESET);
    std::println(std::cout);
  }

  std::vector<const Counter*> rows;
  rows.reserve(snap.counters.size());
  for (const auto& c : snap.counters)
    if (passes(c, f)) rows.push_back(&c);
  if (f.top > 0 && static_cast<int>(rows.size()) > f.top)
    rows.resize(static_cast<std::size_t>(f.top));

  std::string histogram;
  for (const auto* c : rows) {
    // histogram bucket: 0=green, small=blue, mid=yellow, big=red (errors)
    std::string col = C_GREEN;
    if (c->value >= 1000000ull) col = C_RED;
    else if (c->value >= 1000ull) col = C_YELLOW;
    else if (c->value > 0) col = C_BLUE;

    std::string tagstr;
    if (const char* t = tag_of(c->name))
      tagstr = std::string(" (") + t + ")";

    int bucket = c->value == 0 ? 0 : (c->value >= 1000000 ? 3 : (c->value >= 1000 ? 2 : 1));
    histogram.assign(static_cast<std::size_t>(bucket), '#');
    if (histogram.empty()) histogram = ".";

    std::println(std::cout, "  {}{:<26}{} {} {:>15}{}   {}{}{}",
                 C_BOLD, c->name, C_RESET,
                 dir_name(c->dir()),
                 c->value,
                 C_DIM,
                 histogram, tagstr, C_RESET);
  }
  std::println(std::cout, "{}-- {} counters shown --{}", C_DIM, rows.size(), C_RESET);
}

static void render_delta(const Snapshot& prev, const Snapshot& cur, const Filters& f) {
  bool any = false;
  for (const auto& c : cur.counters) {
    if (!passes(c, f)) continue;
    const Counter* p = prev.find(c.name);
    unsigned long long old = p ? p->value : 0;
    if (c.value == old) continue;
    if (!any) {
      std::println(std::cout, "{}-- deltas --{}", C_YELLOW, C_RESET);
      any = true;
    }
    long long d = static_cast<long long>(c.value) - static_cast<long long>(old);
    std::string col = d > 0 ? C_YELLOW : C_GREEN;
    std::println(std::cout, "  {}{:<26}{} {} {:>+12}{}",
                 col, c.name, C_RESET, dir_name(c.dir()), d, C_RESET);
  }
  if (any) std::println(std::cout);
}

static void render_json(std::ostream& os, const Snapshot& snap) {
  os << "{\n  \"ts\": " << snap.ts << ",\n  \"source\": \""
     << (snap.total() == 0 ? "proc" : "proc-or-demo") << "\",\n";
  os << "  \"summary\": {\n"
        "    \"total\": " << snap.total() << ",\n"
        "    \"in\": " << snap.dir_total(Dir::In) << ",\n"
        "    \"out\": " << snap.dir_total(Dir::Out) << ",\n"
        "    \"fwd\": " << snap.dir_total(Dir::Fwd) << ",\n"
        "    \"acq\": " << snap.dir_total(Dir::Acq) << ",\n"
        "    \"nonzero\": " << snap.nonzero_count() << "\n  },\n";
  os << "  \"counters\": [\n";
  bool first = true;
  for (const auto& c : snap.counters) {
    if (!first) os << ",\n";
    first = false;
    os << "    {\"name\": \"" << c.name << "\", \"dir\": \"" << dir_name(c.dir())
       << "\", \"value\": " << c.value << "}";
  }
  os << "\n  ]\n}\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0;
static int g_fail = 0;
static void t_check(bool ok, const char* label) {
  if (ok) {
    ++g_pass;
    std::println(std::cout, "  PASS  {}", label);
  } else {
    ++g_fail;
    std::println(std::cout, "  FAIL  {}", label);
  }
}

static int run_selftest() {
  std::cout << "-- selftest: classification --\n";
  t_check(dir_of("XfrmInError") == Dir::In, "XfrmInError -> in");
  t_check(dir_of("XfrmOutNoStates") == Dir::Out, "XfrmOutNoStates -> out");
  t_check(dir_of("XfrmFwdHdrError") == Dir::Fwd, "XfrmFwdHdrError -> fwd");
  t_check(dir_of("XfrmAcquireError") == Dir::Acq, "XfrmAcquireError -> acq");
  t_check(dir_of("Bogus") == Dir::Unknown, "unknown name -> Unknown");
  t_check(dir_name(Dir::In)[0] == 'i' && dir_name(Dir::Acq)[0] == 'a', "dir_name mapping");

  std::cout << "-- selftest: parser --\n";
  {
    Snapshot s;
    bool ok = load_snapshot(s, "/proc/net/xfrm_stat");
    t_check(ok, "/proc/net/xfrm_stat opens");
    if (ok) {
      t_check(s.counters.size() == 28, "kernel exposes 28 XFRM counters");
      const Counter* c = s.find("XfrmInError");
      t_check(c != nullptr, "XfrmInError present");
      t_check(s.find("XfrmAcquireError") != nullptr, "XfrmAcquireError present");
      std::size_t in_ct = 0;
      for (const auto& cc : s.counters) if (cc.dir() == Dir::In) ++in_ct;
      t_check(in_ct == 14, "kernel exposes 14 inbound counters");
    }
  }

  std::cout << "-- selftest: --file with comments (the README workflow) --\n";
  {
    std::string path = "/tmp/xfrm-watch-selftest.table";
    {
      std::ofstream f(path);
      f << "# snapshot taken from a busy gateway\n"
           "XfrmInError            \t12\n"
           "XfrmInNoStates         \t4217\n"
           "XfrmOutNoStates        \t0\n"
           "XfrmOutPolBlock        \t3\n"
           "   XfrmAcquireError    \t16\n"
           "garbage row that should be skipped\n";
    }
    Snapshot s;
    bool ok = load_snapshot(s, path);
    std::remove(path.c_str());
    t_check(ok, "parse file opens");
    t_check(s.counters.size() == 5, "5 valid rows parsed (garbage+comment skipped)");
    if (s.counters.size() == 5) {
      t_check(s.find("XfrmInError")->value == 12, "XfrmInError = 12");
      t_check(s.find("XfrmInNoStates")->value == 4217, "XfrmInNoStates = 4217");
      t_check(s.find("XfrmAcquireError")->value == 16, "XfrmAcquireError = 16 (trimmed)");
      t_check(s.find("XfrmOutNoStates")->value == 0, "XfrmOutNoStates = 0");
      t_check(s.dir_total(Dir::In) == 4229, "in total = 4229");
    }
  }

  std::cout << "-- selftest: demo --\n";
  {
    Snapshot d;
    bool ok = demo_load(d);
    t_check(ok, "demo loads");
    t_check(d.counters.size() == 28, "demo has 28 counters");
    t_check(d.total() > 0, "demo total > 0");
    t_check(d.nonzero_count() == 19, "demo nonzero = 19");
    t_check(d.dir_total(Dir::In) == 5838, "demo in total = 5838");
    t_check(d.dir_total(Dir::Out) == 722, "demo out total = 722");
    t_check(d.dir_total(Dir::Fwd) == 5, "demo fwd total = 5");
    t_check(d.dir_total(Dir::Acq) == 16, "demo acq total = 16");
    t_check(d.find("XfrmInNoStates")->value == 4217, "demo InNoStates = 4217");
  }

  std::cout << "-- selftest: filters --\n";
  {
    Snapshot d;
    demo_load(d);
    Filters f;
    f.dir = "in";
    std::size_t in_rows = 0;
    for (const auto& c : d.counters) if (passes(c, f)) ++in_rows;
    t_check(in_rows == 14, "dir=in keeps 14 counters");
    f.dir.clear();
    f.nonzero = true;
    std::size_t nz = 0;
    for (const auto& c : d.counters) if (passes(c, f)) ++nz;
    t_check(nz == 19, "nonzero keeps 19 counters");
    f.nonzero = false;
    f.key = "XfrmIn";
    std::size_t k = 0;
    for (const auto& c : d.counters) if (passes(c, f)) ++k;
    t_check(k == 14, "key=XfrmIn keeps 14");
  }

  std::cout << "-- selftest: JSON + --no-color hygiene --\n";
  {
    Snapshot d;
    demo_load(d);
    d.ts = 0;
    std::ostringstream os;
    render_json(os, d);
    std::string j = os.str();
    t_check(j.find("\"XfrmInNoStates\"") != std::string::npos, "json contains counter name");
    t_check(j.find("\"dir\": \"in\"") != std::string::npos, "json has dir in");
    t_check(j.find("\"summary\"") != std::string::npos && j.find("\"counters\"") != std::string::npos,
            "json has summary + counters");

    disable_color();
    Filters f;
    std::ostringstream o2;
    std::streambuf* old = std::cout.rdbuf(o2.rdbuf());
    render_snapshot(d, f, false);
    std::cout.rdbuf(old);
    std::string out = o2.str();
    t_check(out.find("\x1b[") == std::string::npos, "no ANSI codes with --no-color");
    // re-enable for the rest
    C_RESET = "\x1b[0m"; C_BOLD = "\x1b[1m"; C_DIM = "\x1b[2m";
    C_RED = "\x1b[31m"; C_GREEN = "\x1b[32m"; C_YELLOW = "\x1b[33m";
    C_BLUE = "\x1b[34m"; C_CYAN = "\x1b[36m"; C_MAGENTA = "\x1b[35m";
  }

  std::cout << "-- selftest: watch frame (2 iterations, deltas) --\n";
  {
    Snapshot a, b;
    demo_load(a);
    demo_load(b);
    b.counters[0].value += 5;  // XfrmInError +5
    a.ts = 1; b.ts = 2;
    Filters f;
    std::ostringstream o;
    std::streambuf* old = std::cout.rdbuf(o.rdbuf());
    render_delta(a, b, f);
    std::cout.rdbuf(old);
    std::string out = o.str();
    t_check(out.find("XfrmInError") != std::string::npos, "delta render emits changed counter");
    t_check(out.find("+5") != std::string::npos, "delta shows +5");
  }

  std::cout << "selftest: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void print_help() {
  std::cout <<
    "xfrm-watch — XFRM (IPsec) kernel statistics monitor (/proc/net/xfrm_stat)\n"
    "\n"
    "Usage: xfrm-watch [options]\n"
    "\n"
    "  --dir DIR        only direction: in|out|fwd|acq\n"
    "  --key PREFIX     only counters whose name starts with PREFIX (e.g. XfrmIn)\n"
    "  --nonzero        only counters with value > 0\n"
    "  --top N          limit rows shown\n"
    "  --watch N        refresh every N seconds with deltas\n"
    "  --json           machine-readable output\n"
    "  --demo           synthetic busy VPN gateway (nonzero counters)\n"
    "  --file PATH      parse a dump instead of /proc\n"
    "  --no-color       disable ANSI colors\n"
    "  --selftest       run self-tests and exit\n"
    "  -h, --help       this help\n";
}

int main(int argc, char** argv) {
  Filters f;
  bool color_flag = true;
  bool demo = false;
  bool json = false;
  int watch = 0;
  std::string file;
  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next = [&](std::string_view name) -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "error: " << name << " requires a value\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };
    if (a == "--dir")     { auto v = next(a); if (!v) return 2; f.dir = *v; }
    else if (a == "--key") { auto v = next(a); if (!v) return 2; f.key = *v; }
    else if (a == "--file") { auto v = next(a); if (!v) return 2; file = *v; }
    else if (a == "--top")  { auto v = next(a); if (!v) return 2; f.top = std::atoi(v->c_str()); }
    else if (a == "--watch") { auto v = next(a); if (!v) return 2; watch = std::atoi(v->c_str()); }
    else if (a == "--nonzero") f.nonzero = true;
    else if (a == "--demo")   demo = true;
    else if (a == "--json")   json = true;
    else if (a == "--no-color") color_flag = false;
    else if (a == "--selftest") return run_selftest();
    else if (a == "-h" || a == "--help") { print_help(); return 0; }
    else { std::cerr << "error: unknown option '" << a << "' (see --help)\n"; return 2; }
  }

  if (!color_flag) disable_color();

  std::string source = file.empty() ? "/proc/net/xfrm_stat" : file;

  if (watch > 0) {
    Snapshot prev;
    bool first = true;
    for (;;) {
      Snapshot cur;
      cur.ts = std::chrono::duration_cast<std::chrono::seconds>(
                 std::chrono::system_clock::now().time_since_epoch()).count();
      bool ok = demo ? demo_load(cur) : load_snapshot(cur, source);
      if (!ok) {
        std::cerr << "error: cannot read " << source << "\n";
        return 1;
      }
      if (!first) render_delta(prev, cur, f);
      render_snapshot(cur, f, !first);
      prev = std::move(cur);
      first = false;
      std::cout << std::flush;
      std::this_thread::sleep_for(std::chrono::seconds(watch));
    }
  }

  Snapshot snap;
  snap.ts = std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch()).count();
  bool ok = demo ? demo_load(snap) : load_snapshot(snap, source);
  if (!ok) {
    std::cerr << "error: cannot read " << source << "\n";
    return 1;
  }
  if (json) render_json(std::cout, snap);
  else render_snapshot(snap, f, false);
  return 0;
}