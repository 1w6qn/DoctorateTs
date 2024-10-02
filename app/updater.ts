import config from "./config";
import { EventEmitter } from "events";
import axios from "axios";

export class Updater {
  _trigger: EventEmitter;

  constructor() {
    this._trigger = new EventEmitter();
  }

  async init() {
    this._trigger.on("refresh:version", this.refreshVersion.bind(this));
    if (config.assets.autoUpdate) {
      //
    }
  }

  async refreshVersion() {
    await axios.get("");
  }
}

export const updater = new Updater();
