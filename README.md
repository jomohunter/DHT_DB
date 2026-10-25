# DHT_DB — A Distributed Hash Table in C++

A learning project to understand how decentralized, peer-to-peer systems work by building a simplified **Kademlia-inspired Distributed Hash Table (DHT)** from scratch in C++.

The goal is to explore how nodes can discover each other and locate distributed key-value data without relying on a central server.

## Why This Project?

I wanted to go beyond using distributed systems as black boxes and understand the mechanisms behind them. Building a DHT from scratch gives me a practical way to explore peer-to-peer networking, routing, hashing, and the challenges of designing decentralized systems.

## Tech Stack

- **C++17** — core implementation
- **SHA-1** — generating 160-bit node IDs and keys
- **UDP** — planned transport layer for communication between nodes
- **Kademlia-inspired routing** — XOR distance and k-buckets

## Architecture

The project is organized around a few core components:

- **Identifiers:** Represent nodes and keys in a 160-bit identifier space.
- **Routing Table:** Organizes known nodes into distance-based buckets to help locate nearby nodes.
- **Message Protocol:** Defines the structure of messages exchanged between nodes.
- **Transport Layer:** Provides the foundation for UDP communication.
- **Node:** Intended to coordinate routing, storage, and communication.

## What I've Implemented

- 160-bit node and key identifiers.
- SHA-1-based identifier generation.
- XOR distance calculations for comparing identifiers.
- A Kademlia-style routing table with 160 buckets and a maximum of 8 contacts per bucket.
- Routing-table tests covering insertion and lookup behavior.
- Initial message-protocol and UDP transport components.

## What I'm Learning

Working on this project has helped me understand:

- How DHTs map keys and nodes into a shared identifier space.
- Why XOR distance is useful for decentralized routing.
- How k-buckets organize peers by distance.
- How to separate routing, networking, and node-level logic into modular components.
- Why implementing a distributed system requires more than simply sending data between machines.

## Current Status

**Work in progress.** The identifier and routing-table foundations are implemented and tested. Message serialization and UDP transport are under development.

The next steps are to complete node-to-node communication, implement the necessary RPC operations, add key-value storage, and test lookups across multiple independent nodes.

## Project Goal

Build a minimal working DHT that allows independent nodes to communicate and locate stored key-value pairs without a central coordinator.

This project
