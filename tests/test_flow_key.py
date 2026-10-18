import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from visibility.flow_key import make_flow_id, forward_tuple_from_packet


def test_flow_id_bidirectional():
    a = make_flow_id(6, "10.0.0.1", 12345, "10.0.0.2", 443, )
    b = make_flow_id(6, "10.0.0.2", 443, "10.0.0.1", 12345, )
    assert a == b


def test_forward_order():
    t = forward_tuple_from_packet("10.0.0.1", "10.0.0.2", 50000, 443, 6)
    assert t[0] == "10.0.0.1" and t[1] == 50000 and t[2] == "10.0.0.2" and t[3] == 443
