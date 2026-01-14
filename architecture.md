# System Architecture

## Objective
Detect and mitigate ransomware attacks using decentralized learning
while preserving endpoint privacy.

## High-Level Architecture
- Endpoint agents monitor system behavior
- Local models are trained on-device
- Federated aggregation updates global model
- Radar dashboard visualizes threat patterns

## Components
### Endpoint Agent
- Collects behavioral metrics
- Runs local inference
- Sends encrypted model updates

### Federated Learning Server
- Aggregates client updates
- Distributes global model

### Radar Dashboard
- Real-time visualization
- Threat severity indicators

## Threat Model
- File encryption spikes
- Abnormal I/O patterns
- Process injection behavior

## Deployment
- Windows executable distribution
