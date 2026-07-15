import { PlayerRoguelikeV2 } from "@game/model/rlv2";
import { RoguelikeV2Controller } from "../../rlv2";
import { TypedEventEmitter } from "@game/model/events";
import excel from "@excel/excel";

export class RoguelikeTotemManager {
  _totemPiece: PlayerRoguelikeV2.CurrentData.Module.InventoryTotem[];
  _predictTotemId: string | undefined;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._totemPiece = [];
    this._trigger = _trigger;
    this._trigger.on("rlv2:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
  }

  use(totemIndex: [string, string], nodeIndex: string[]) {
    const [upperInstId, lowerInstId] = totemIndex;
    const theme = this._player.current.game!.theme;
    const totemData = excel.RoguelikeTopicTable.modules[theme].totemBuff;

    const upperTotem = this._totemPiece.find((t) => t.instId === upperInstId);
    const lowerTotem = this._totemPiece.find((t) => t.instId === lowerInstId);
    if (!upperTotem || !lowerTotem) {
      return;
    }

    const upperId = upperTotem.id;
    const lowerId = lowerTotem.id;

    const upperColor = totemData?.totemBuffDatas[upperId]?.color || "";
    const lowerColor = totemData?.totemBuffDatas[lowerId]?.color || "";

    const extraEffect = upperColor === lowerColor;

    const zone = this._player._status.cursor.zone;

    const selectedNodeDict: { [key: string]: any } = {};
    const selectedNodePos: string[] = [];

    const reachableNodes = this._getReachableNodes(zone);
    for (const nodeId of Object.keys(reachableNodes)) {
      if (nodeId !== nodeIndex[0]) {
        selectedNodeDict[nodeId] = reachableNodes[nodeId];
        selectedNodePos.push(nodeId);
      }
    }

    if (nodeIndex[0]) {
      selectedNodeDict[nodeIndex[0]] = this._player._map.zones[zone]?.nodes[nodeIndex[0]];
      selectedNodePos.push(nodeIndex[0]);
    }

    const upperBuffData = totemData?.totemBuffDatas[upperId];
    const lowerBuffData = totemData?.totemBuffDatas[lowerId];

    const attachBuff: string[] = [];
    if (lowerBuffData?.linkedNodeTypeData?.effectiveNodeTypes) {
      for (const nodeType of lowerBuffData.linkedNodeTypeData.effectiveNodeTypes) {
        attachBuff.push(nodeType);
      }
    }

    for (const nodePos of selectedNodePos) {
      const node = this._player._map.zones[zone]?.nodes[nodePos];
      if (!node) continue;

      if (extraEffect && upperBuffData?.linkedNodeTypeData?.effectiveNodeTypes) {
        for (const nodeType of upperBuffData.linkedNodeTypeData.effectiveNodeTypes) {
          if (!attachBuff.includes(nodeType)) {
            attachBuff.push(nodeType);
          }
        }
      }

      if (attachBuff.length > 0) {
        if (!node.attach) {
          node.attach = [];
        }
        node.attach.push(...attachBuff);
      }
    }

    upperTotem.used = true;
    lowerTotem.used = true;

    this._trigger.emit("rlv2:node:attach", [selectedNodePos, attachBuff]);
  }

  private _getReachableNodes(zone: number): { [key: string]: any } {
    const nodes: { [key: string]: any } = {};
    const zoneData = this._player._map.zones[zone];
    if (!zoneData) return nodes;

    const visited = new Set<string>();
    const queue: string[] = [];

    if (this._player._status.cursor.position) {
      const currentId = `${this._player._status.cursor.position.x * 100 + this._player._status.cursor.position.y}`;
      if (zoneData.nodes[currentId]) {
        queue.push(currentId);
        visited.add(currentId);
      }
    } else {
      for (const [id, node] of Object.entries(zoneData.nodes)) {
        if (node.pos.x === 0) {
          queue.push(id);
          visited.add(id);
        }
      }
    }

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      const currentNode = zoneData.nodes[currentId];

      for (const next of currentNode.next || []) {
        const nextId = `${next.x * 100 + next.y}`;
        if (!visited.has(nextId) && zoneData.nodes[nextId]) {
          visited.add(nextId);
          queue.push(nextId);
          nodes[nextId] = zoneData.nodes[nextId];
        }
      }
    }

    return nodes;
  }

  init() {
    const theme = this._player.current.game!.theme;
    this._totemPiece = [];
  }

  continue() {
    this._totemPiece = this._player.current.module!.totem!.totemPiece;
    this._predictTotemId = this._player.current.module!.totem!.predictTotemId;
  }

  toJSON(): PlayerRoguelikeV2.CurrentData.Module.Totem {
    return {
      totemPiece: this._totemPiece,
      predictTotemId: this._predictTotemId,
    };
  }
}
