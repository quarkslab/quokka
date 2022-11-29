# Functions features

## Original code

```python
# From https://github.com/Cisco-Talos/binary_function_similarity/blob/main/IDA_scripts/IDA_acfg_features/core/ff_features.py#L76
def get_function_features(fva, bbs_dict, len_edges):
    """
    Construction the dictionary with function-level features.
    Args:
        fva: function virtual address
        bbs_dict: a dictionary with all the features, one per BB
        len_eges: number of edges
    Return:
        a dictionary with function-level features
    """
    f_dict = {
        'n_func_calls': f_sum(bbs_dict, 'n_call_instrs'),
        'n_logic_instrs': f_sum(bbs_dict, 'n_logic_instrs'),
        'n_redirections': f_sum(bbs_dict, 'n_redirect_instrs'),
        'n_transfer_instrs': f_sum(bbs_dict, 'n_transfer_instrs'),
        'size_local_variables': get_size_local_vars(fva),
        'n_bb': len(bbs_dict),
        'n_edges': len_edges,
        'n_incoming_calls': get_func_incoming_calls(fva),
        'n_instructions': f_sum(bbs_dict, 'n_instructions')
    }
    return f_dict

```

## Quokka code

```python
import quokka

FeaturesDict = ...

def sum_block_features(bb_features: FeaturesDict, feature: str) -> int:
    """Sum the values for every basic block in the function"""
    assert feature.startswith("n_"), "Only numeric values can be summed"
    return sum(basic_block[feature] for basic_block in bb_features.values())


def get_func_features(func: quokka.Function) -> FeaturesDict:
    bb_features = {}
    for block_start in func.graph:
        block = func.get_block(block_start)
        bb_features[block_start] = get_bb_features(block)
        
    return {
        'n_func_calls': sum_block_features(bb_features, 'n_call_instrs'),
        'n_logic_instrs': sum_block_features(bb_features, 'n_logic_instrs'),
        'n_redirections': sum_block_features(bb_features, 'n_redirect_instrs'),
        'n_transfer_instrs': sum_block_features(bb_features, 'n_transfer_instrs'),
        'size_local_variables': ..., # Not possible with Quokka
        'n_bb': len(bb_features),
        'n_edges': len(func.graph.edges),
        'n_incoming_calls': len(func.callers),
        'n_instructions': sum(1 for _ in func.instructions),
        "basic_blocks": bb_features,
    }
```

Et voilà!