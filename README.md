# B01lers CTF 2026 — Writeups

Writeup cho 2 challenge web mình giải trong **B01lers CTF 2026**.

## Thành tích team

| | |
|---|---|
| **Team** | UIT-creampie |
| **Hạng** | **11** / all teams · **11** / Open division |
| **Điểm** | 7825 |
| **Division** | Open |

Strong category: web & rev (xem radar trong [scoreboard.md](./scoreboard.md)).

## Challenges

| | Challenge | Category | Hướng giải ngắn gọn |
|---|---|---|---|
| 1 | [`egg`](./egg) | Web | Forge cookie với `session_timestamp = NaN` để cố định `egg_id`, race 2 account A/B trên `POST /eggs` để mix DB ownership với file payload, hatch để đọc `/proc/1/cmdline` |
| 2 | [`clankers-market`](./clankers-market) | Web | Ghi đè `.git/index` (Git index v4 path compression né `grep 'git'`), ép `git-dumper` `git checkout` chạy `post-checkout` hook leak flag qua SUID helper |

Mỗi folder có:

```
<challenge>/
├── README.md       --> writeup chi tiết
├── solve.py        --> exploit script đầy đủ, chạy được
├── challenge/      --> source code đề
└── screenshots/
```

## Setup nhanh

```bash
# egg
pip install itsdangerous
python3 egg/solve.py --base http://HOST:8000

# clankers-market
pip install requests
python3 clankers-market/solve.py http://HOST:5000
```

## Liên hệ

- Portfolio: <https://trangtuananh.github.io/Portforlio/>
- GitHub: [@TrangTuanAnh](https://github.com/TrangTuanAnh)
