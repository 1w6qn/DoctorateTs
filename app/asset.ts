import { Router } from "express";
import config from "./config"
const router = Router();
router.get("/official/Android/assets/:assetsHash/:fileName", (req, res) => {
    
    if(config.enableMods){
        //TODO: implement mod support
    }else{
        return res.redirect(`https://ak.hycdn.cn/assetbundle/official/Android/assets/${config.version.resVersion}/${req.params.fileName}`)
    }
});
export default router;