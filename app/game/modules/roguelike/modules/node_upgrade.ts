import { PlayerRoguelikeV2 } from "../rlv2";
import { RoguelikeV2Manager } from "../logic";
import excel from "@excel/excel";
import { randomChoice } from "@utils/random";
import { TypedEventEmitter } from "../../../kernel/events/runtime";

export class RoguelikeNodeUpgradeManager {
  _nodeTypeInfoMap: {
    [key: string]: PlayerRoguelikeV2.CurrentData.Module.NodeUpgradeInfo;
  };
  _player: RoguelikeV2Manager;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Manager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._nodeTypeInfoMap = {};
    this._trigger = _trigger;
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:node:upgrade", this.upgrade.bind(this));
  }

  init() {
    const theme = this._player.current.game!.theme;
    // 防御：跨主题残留管理器（上一局其他主题的 manager 仍订阅 module:init）
    // 当前主题无 nodeUpgrade 数据时直接跳过，避免 null 解引用
    const nodeUpgradeInfo = this._player.outer[theme]?.collect?.nodeUpgrade;
    const tempMap = (excel.RoguelikeTopicTable.modules[theme] as any)
      ?.nodeUpgrade?.nodeUpgradeDataMap;
    if (!nodeUpgradeInfo || !tempMap) {
      this._nodeTypeInfoMap = {};
      return;
    }
    this._nodeTypeInfoMap = Object.fromEntries(
      Object.entries(nodeUpgradeInfo).map(([k, v]) => {
        const upgradeList = v.unlockList;
        const tempList = tempMap[k].tempItemList;
        return [
          k,
          {
            tempUpgrade:
              upgradeList.length < 5
                ? ""
                : randomChoice(
                    tempList.map(
                      (item: { upgradeId: string }) => item.upgradeId,
                    ),
                  ),
            upgradeList: upgradeList,
            currUpgradeIndex: upgradeList.length - 1,
          },
        ];
      }),
    );
  }

  continue() {
    this._nodeTypeInfoMap =
      this._player.current.module!.nodeUpgrade!.nodeTypeInfoMap;
  }

  async upgrade([nodeType]: [string]) {
    const theme = this._player.current.game!.theme;
    const info = this._nodeTypeInfoMap[nodeType];
    // 防御：未知节点类型不 500
    if (!info) return;
    const tempMap =
      excel.RoguelikeTopicTable.modules[theme].nodeUpgrade!.nodeUpgradeDataMap;
    // 修复：原实现 temp 分支不递增 currUpgradeIndex → 同一临时升级无限重复（且
    // 只 push 内存 upgradeList 不落盘）；tempUpgrade 为 "" 时 find(...)! 崩溃。
    // 统一：<4 永久升级递增；==4 临时升级仅一次（置 5 完成）；>=5 无操作
    if (info.currUpgradeIndex < 4) {
      const permItem = tempMap[nodeType]?.permItemList?.find(
        (item) => item.nodeLevel == info.currUpgradeIndex + 1,
      );
      if (!permItem) return; // 防御：配置缺失
      info.currUpgradeIndex += 1;
      info.upgradeList.push(permItem.upgradeId);
      // outer[theme].collect 为 _playerdata.rlv2 引用（update() 后冻结），写入须放入配方
      await this._player.update(async (draft) => {
        (draft.outer[theme] as any).collect.nodeUpgrade[nodeType].unlockList.push(
          permItem.upgradeId,
        );
      });
      this._trigger.emit("rlv2:fragment:use", [
        permItem.costItemId,
        permItem.costItemCount,
      ]);
    } else if (info.currUpgradeIndex === 4) {
      info.currUpgradeIndex = 5; // 临时升级只做一次，之后标记完成
      if (!info.tempUpgrade) return; // 无临时升级配置（长度不足）——跳过不崩溃
      const tempItem = tempMap[nodeType]?.tempItemList?.find(
        (item) => item.upgradeId == info.tempUpgrade,
      );
      if (!tempItem) return; // 防御：配置缺失
      info.upgradeList.push(tempItem.upgradeId);
      await this._player.update(async (draft) => {
        (draft.outer[theme] as any).collect.nodeUpgrade[nodeType].unlockList.push(
          tempItem.upgradeId,
        );
      });
      this._trigger.emit("rlv2:fragment:use", [
        tempItem.costItemId,
        tempItem.costItemCount,
      ]);
    }
    // currUpgradeIndex >= 5：已完成，无操作
  }

  toJSON(): PlayerRoguelikeV2.CurrentData.Module.NodeUpgrade {
    return {
      nodeTypeInfoMap: this._nodeTypeInfoMap,
    };
  }
}
