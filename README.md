# Stock Savvy

## Table of Contents

1. [Overview](#Overview)
2. [Product Spec](#Product-Spec)

## Overview

#### Description

Stock Savvy is a fully functional website that allows users to manage their individual stock portfolios.

## Product Spec

#### Features Implemented: 
- [x] Users are allowed to register, log in, and manage accounts, utilizing password hashing for enhanced security.
- [x] Real-time stock prices are used to ensure information is accurate and up to date.
- [x] Users' holdings are calculated and displayed based on real-time stock prices.
- [x] Users can view stock quotes.
- [x] Users can execute buy / sell transactions.
- [x] Users can view their transaction history.


#### Upcoming Features:
+ Users will have a more personalized experience.

### Video Walkthrough:

Check out the following video to see it functioning in action!

[![Video Thumbnail](https://img.youtube.com/vi/5LNKwCcenC8/hqdefault.jpg)](https://www.youtube.com/watch?v=5LNKwCcenC8)

#### SQLite Schema
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username TEXT NOT NULL,
    hash TEXT NOT NULL,
    cash NUMERIC NOT NULL DEFAULT 10000.00
);
CREATE UNIQUE INDEX username ON users (username);
CREATE TABLE stock_record (
    transaction_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id INTEGER NOT NULL,
    stock TEXT NOT NULL,
    shares INTEGER NOT NULL,
    price NUMERIC NOT NULL,
    total_price NUMERIC NOT NULL,
    time TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

