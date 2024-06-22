import express from 'express';
import prod from "./app/config/prod"
import config from './app/config';
const app = express();

app.use("/config/prod",prod)
app.get('/', (req, res) => {
  res.send('Hello world');
});
 
app.listen(config.PORT, () => {
  console.log(`Express with Typescript! http://localhost:${config.PORT}`);
});