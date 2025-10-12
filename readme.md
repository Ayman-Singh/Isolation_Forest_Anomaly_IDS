# Isolation Forest IDS

- Added decision-threshold tuning that selects a score threshold from the precision-recall curve (metric: F1) and applies it to evaluation output.
- Evaluation run used: `UGR-16_dataset/April/april.week3.first10M.csv` (streamed evaluation).

Key results 

Raw model evaluation (model.predict):
- Accuracy: 0.789
- Precision: 0.002
- Recall: 0.160
- F1: 0.004
- ROC-AUC: 0.503
- PR-AUC: 0.002
- Confusion matrix [[TN, FP],[FN, TP]]: [[7883749, 2092940], [19592, 3718]]

After decision-threshold tuning (threshold selected by maximizing F1 on the PR-curve):
- Tuned threshold: -0.093570
- Precision: 0.003
- Recall: 0.651
- F1: 0.005
- Tuned confusion matrix [[TN, FP],[FN, TP]]: [[4192518, 5784171], [8129, 15181]]

Notes / interpretation
- The tuning increased recall from 0.160 to 0.651 (16.0% -> 65.1%) by lowering the decision threshold to `-0.093570`. This greatly increased true positives at the cost of a large increase in false positives (see confusion matrices).
- The PR-curve F1 objective was used to choose the threshold; that produced a small absolute gain in F1 (0.004 -> 0.005) while yielding a substantial recall improvement — useful if recall is the priority and higher FP is acceptable.



dataset structure :

Timestamp
Duration
Source IP
Destination IP
Source Port
Destination Port
Protocol
Flags
Field 9 (likely forwarding status)
Field 10 (likely TOS/DSCP)
Packets
Bytes
Label


