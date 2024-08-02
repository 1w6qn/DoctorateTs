import { PlayerRoguelikeV2 } from "../../../model/rlv2"
import EventEmitter from "events"
import { RoguelikeV2Controller } from '../../RoguelikeV2Controller';
import excel from "@excel/excel";
import { randomChoice } from "@utils/random";

export class RoguelikeNodeUpgradeManager {
    _nodeTypeInfoMap: { [key: string]: PlayerRoguelikeV2.CurrentData.Module.NodeUpgradeInfo }
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._player = player
        this._nodeTypeInfoMap = {}
        this._trigger = _trigger
        this._trigger.on("rlv2:module:init", this.init.bind(this))
        this._trigger.on("rlv2:continue", this.continue.bind(this))
        this._trigger.on("rlv2:node:upgrade", this.upgrade.bind(this))
    }
    init() {
        const theme = this._player.current.game!.theme
        const nodeUpgradeInfo = this._player.outer[theme].collect.nodeUpgrade
        const tempMap = excel.RoguelikeTopicTable.modules[theme].nodeUpgrade!.nodeUpgradeDataMap
        this._nodeTypeInfoMap = Object.fromEntries(Object.entries(nodeUpgradeInfo).map(([k, v]) => {
            let upgradeList = v.unlockList
            let tempList = tempMap[k].tempItemList
            return [k, {
                tempUpgrade: upgradeList.length < 5 ? "" : randomChoice(tempList.map((item) => item.upgradeId)),
                upgradeList: upgradeList,
                currUpgradeIndex: upgradeList.length - 1
            }]
        }))
    }
    continue() {
        this._nodeTypeInfoMap = this._player.current.module!.nodeUpgrade!.nodeTypeInfoMap
    }
    upgrade(nodeType: string) {
        const theme = this._player.current.game!.theme
        const tempMap = excel.RoguelikeTopicTable.modules[theme].nodeUpgrade!.nodeUpgradeDataMap
        if (this._nodeTypeInfoMap[nodeType].currUpgradeIndex == 4) {
            let tempItem = tempMap[nodeType].tempItemList
                .find((item) => item.upgradeId == this._nodeTypeInfoMap[nodeType].tempUpgrade)!;
            this._nodeTypeInfoMap[nodeType].upgradeList.push(tempItem.upgradeId)
            this._trigger.emit("rlv2:fragment:use", tempItem.costItemId, tempItem.costItemCount)
        } else {
            let permItem = tempMap[nodeType].permItemList
                .find((item) => item.nodeLevel == this._nodeTypeInfoMap[nodeType].currUpgradeIndex + 1)!;
            this._nodeTypeInfoMap[nodeType].currUpgradeIndex += 1
            this._nodeTypeInfoMap[nodeType].upgradeList.push(permItem.upgradeId)
            this._player.outer[theme].collect.nodeUpgrade[nodeType].unlockList.push(permItem.upgradeId)
            this._trigger.emit("rlv2:fragment:use", permItem.costItemId, permItem.costItemCount)
        }
        
    }
    toJSON(): PlayerRoguelikeV2.CurrentData.Module.NodeUpgrade {
        return {
            nodeTypeInfoMap: this._nodeTypeInfoMap
        }
    }
}