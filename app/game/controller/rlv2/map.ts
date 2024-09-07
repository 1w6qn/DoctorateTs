import { EventEmitter } from "events"
import { PlayerRoguelikeNode, PlayerRoguelikeV2Dungeon, PlayerRoguelikeV2Zone, RoguelikeBuff } from '../../model/rlv2';
import { RoguelikeV2Controller } from '../rlv2';


export class RoguelikeMapManager implements PlayerRoguelikeV2Dungeon {
    zones: { [key: string]: PlayerRoguelikeV2Zone }
    _player: RoguelikeV2Controller
    _trigger: EventEmitter

    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this.zones = {}
        this._player = player
        this._trigger = _trigger
        this._trigger.on('rlv2:init', this.init.bind(this))
        this._trigger.on("rlv2:create", this.create.bind(this))
        this._trigger.on("rlv2:zone:new", this.generate.bind(this))

    }
    init() {
        this.zones = {}
    }
    create() {
        this.zones = {}
    }
    generate(id: number) {
        this._player._buff.filterBuffs("zone_into_reward").forEach(b => {
            if (b.blackboard[2].value == id) {
                this._trigger.emit("rlv2:get:items", { id: b.blackboard[0].valueStr, count: b.blackboard[1].value })
            }
        })
        this._player._buff.filterBuffs("zone_into_cost").forEach(b => {
            if (b.blackboard[2].value == id) {
                this._trigger.emit("rlv2:get:items", { id: b.blackboard[0].valueStr, count: -b.blackboard[1].value! })
            }
        })
        this._player._buff.filterBuffs("zone_into_buff").forEach(b => {
            let buff:RoguelikeBuff = {
                key: b.blackboard[0].valueStr!,
                blackboard: b.blackboard.slice(1),
            }
            this._player._buff.applyBuffs(buff)
        })
        //TODO
        this.zones[id] = {
            "id": "zone_" + id,
            "index": id,
            "nodes": {
                "0": {
                    "index": "0",
                    "pos": {
                        "x": 0,
                        "y": 0
                    },
                    "next": [
                        {
                            "x": 1,
                            "y": 0
                        }
                    ],
                    "type": 1,
                    "refresh": {
                        "usedCount": 0,
                        "count": 1,
                        "cost": 1
                    },
                    "stage": "ro4_n_1_4"
                },
                "1": {
                    "index": "1",
                    "pos": {
                        "x": 0,
                        "y": 1
                    },
                    "next": [
                        {
                            "x": 1,
                            "y": 1
                        },
                        {
                            "x": 1,
                            "y": 2
                        }
                    ],
                    "type": 1,
                    "refresh": {
                        "usedCount": 0,
                        "count": 1,
                        "cost": 1
                    },
                    "stage": "ro4_n_1_1",
                    "fts": 1722149443
                },
                "100": {
                    "index": "100",
                    "pos": {
                        "x": 1,
                        "y": 0
                    },
                    "next": [
                        {
                            "x": 2,
                            "y": 0
                        }
                    ],
                    "type": 32,
                    "refresh": {
                        "usedCount": 0,
                        "count": 1,
                        "cost": 1
                    }
                },
                "101": {
                    "index": "101",
                    "pos": {
                        "x": 1,
                        "y": 1
                    },
                    "next": [
                        {
                            "x": 2,
                            "y": 1
                        },
                        {
                            "x": 1,
                            "y": 2,
                            "key": true
                        }
                    ],
                    "type": 32,
                    "refresh": {
                        "usedCount": 0,
                        "count": 1,
                        "cost": 1
                    }
                },
                "102": {
                    "index": "102",
                    "pos": {
                        "x": 1,
                        "y": 2
                    },
                    "next": [
                        {
                            "x": 2,
                            "y": 1
                        },
                        {
                            "x": 1,
                            "y": 1,
                            "key": true
                        }
                    ],
                    "type": 2,
                    "refresh": {
                        "usedCount": 0,
                        "count": 1,
                        "cost": 1
                    }
                },
                "200": {
                    "index": "200",
                    "pos": {
                        "x": 2,
                        "y": 0
                    },
                    "next": [
                        {
                            "x": 3,
                            "y": 0
                        },
                        {
                            "x": 2,
                            "y": 1,
                            "key": true
                        }
                    ],
                    "type": 32,
                    "refresh": {
                        "usedCount": 0,
                        "count": 1,
                        "cost": 1
                    }
                },
                "201": {
                    "index": "201",
                    "pos": {
                        "x": 2,
                        "y": 1
                    },
                    "next": [
                        {
                            "x": 3,
                            "y": 0
                        },
                        {
                            "x": 2,
                            "y": 0,
                            "key": true
                        }
                    ],
                    "type": 32,
                    "refresh": {
                        "usedCount": 0,
                        "count": 1,
                        "cost": 1
                    }
                },
                "300": {
                    "index": "300",
                    "pos": {
                        "x": 3,
                        "y": 0
                    },
                    "next": [],
                    "type": 4096,
                    "zone_end": true,
                    "refresh": {
                        "usedCount": 0,
                        "count": 1,
                        "cost": 1
                    }
                }
            },
            "variation": []
        }
    }
    findNode( zone_id: number,pos:{x: number, y: number},): PlayerRoguelikeNode {
        return this.zones[zone_id].nodes[100 * pos.x + pos.y]
    }
    toJSON(): PlayerRoguelikeV2Dungeon {
        return {
            zones: this.zones
        }
    }
}

