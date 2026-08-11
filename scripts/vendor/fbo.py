"""FlatBuffers Objects (FBO) 解码器（自包含，从 Ark-Unpacker 提取）
将 Arknights excel FBO 二进制解码为 JSON 可序列化 dict。
依赖：numpy（仅用于 ndarray 处理）+ flatbuffers（schema 自带）。
"""
import math
from collections import defaultdict
from typing import Callable, Union
import numpy as np

class CompatibleFloat(float):
    def __new__(cls, value: float):
        f32 = CompatibleFloat.truncate(value, 7)
        f64 = CompatibleFloat.truncate(value, 16)
        return super().__new__(cls, f64 if f32 == f64 else f32)

    @staticmethod
    def truncate(value: float, precision: int) -> str:
        if value == 0.0:
            return "0.0"
        l_digits = int(math.floor(math.log10(value if value > 0.0 else -value))) + 1
        r_digits = precision - l_digits if l_digits < precision else 0
        formatted = f"{value:.{r_digits}f}".rstrip("0")
        return formatted + "0" if formatted.endswith(".") else formatted



class FBOHandler:
    """Handler for FlatBuffers Objects, implementing conversion to Python dict type."""

    SERIALIZE_AS_IS = Union[bool, int, str, list, tuple, dict, None]
    SERIALIZE_AS_STR = Union[bytes, bytearray, memoryview]
    SERIALIZE_ENCODING = None  # Will be dynamically retrieved

    def __init__(self, data: bytearray, root_type: type):
        self._root = root_type.GetRootAs(data, 0)

    @staticmethod
    def _get_serialize_encoding():
        if FBOHandler.SERIALIZE_ENCODING is None:
            FBOHandler.SERIALIZE_ENCODING = "utf-8"
        return FBOHandler.SERIALIZE_ENCODING

    @staticmethod
    def _to_literal(obj: object):
        if isinstance(obj, float):
            return CompatibleFloat(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, FBOHandler.SERIALIZE_AS_IS):
            return obj
        if isinstance(obj, FBOHandler.SERIALIZE_AS_STR):
            return str(
                obj,
                encoding=FBOHandler._get_serialize_encoding(),
                errors="surrogateescape",
            )
        return FBOHandler._to_json_dict(obj)

    @staticmethod
    def _is_pure_kv(obj: object) -> bool:
        """对象是否仅含 Key/Value 数据字段（可折叠为 {key: value} 的纯键值对）。
        Blackboard_DataPair 含 ValueStr 等额外字段 → 返回 False，须保留完整对象。"""
        for n in dir(obj):
            if n in ("Init", "Clear") or n.startswith(("_", "GetRootAs")) or n == "IsNone":
                continue
            base = n[:-6] if n.endswith(("IsNone", "Length")) else n
            if base not in ("Key", "Value"):
                return False
        return True

    @staticmethod
    def _to_json_dict(obj: object):
        if obj is None:
            return None

        data = {}

        f_obj_key = getattr(obj, "Key", None)
        f_obj_value = getattr(obj, "Value", None)
        f_obj_value_len = getattr(obj, "ValueLength", None)

        if f_obj_key and f_obj_value and FBOHandler._is_pure_kv(obj):
            # As key-value item:
            assert isinstance(f_obj_key, Callable) and isinstance(f_obj_value, Callable)
            if f_obj_value_len:
                # Value is array
                assert isinstance(f_obj_value_len, Callable)
                data[FBOHandler._to_literal(f_obj_key())] = [
                    FBOHandler._to_literal(f_obj_value(i)) for i in range(f_obj_value_len())
                ]
            else:
                # Value is single
                data[FBOHandler._to_literal(f_obj_key())] = FBOHandler._to_literal(f_obj_value())
        else:
            # As table object:
            # Collect field names
            field_name_map = defaultdict(lambda: [None, None, None])
            for field_name in dir(obj):
                if field_name in ("Init", "Clear"):
                    continue
                elif field_name.startswith(("_", "GetRootAs")):
                    continue
                elif field_name != "IsNone" and field_name.endswith("IsNone"):
                    field_name_map[field_name[:-6]][0] = getattr(obj, field_name, None)
                elif field_name != "Length" and field_name.endswith("Length"):
                    field_name_map[field_name[:-6]][1] = getattr(obj, field_name, None)
                else:
                    field_name_map[field_name][2] = getattr(obj, field_name, None)

            # Collect field values
            for field_name, (
                f_field_is_none,
                f_field_len,
                f_field,
            ) in field_name_map.items():
                if isinstance(f_field, Callable):
                    value = None
                    if isinstance(f_field_is_none, Callable) and f_field_is_none():
                        # Value is explicit null
                        continue
                    elif isinstance(f_field_len, Callable):
                        # Value is table or array
                        field_len = f_field_len()
                        if field_len:
                            if FBOHandler._is_pure_kv(f_field(0)):
                                # 纯键值对表数组 → 折叠为 dict
                                value = {}
                                for i in range(field_len):
                                    item = FBOHandler._to_json_dict(f_field(i))
                                    assert isinstance(item, dict)
                                    value.update(item)
                            else:
                                # 标量数组 / 表数组（含 DataPair 等带额外字段的对象）→ 保留为列表
                                value = [FBOHandler._to_literal(f_field(i)) for i in range(field_len)]
                        else:
                            # TODO handle empty table
                            pass
                    else:
                        # Value is common literal
                        value = FBOHandler._to_literal(f_field())
                    # Add this field to the object data
                    data[field_name] = value

        # Return the whole object data
        return data

    def to_json_dict(self):
        return FBOHandler._to_json_dict(self._root)

