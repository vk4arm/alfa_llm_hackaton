import os
import sys
sys.path.append(os.path.abspath('../../data'))
from create_datasets import build_dataset_to_size

out_dir = os.path.abspath("../../data/pii_samples")
build_dataset_to_size(5 * 1024 * 1024, os.path.join(out_dir, "pii_dataset_5mb.txt"))
