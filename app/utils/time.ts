import moment from "moment";
import StartOf = moment.unitOfTime.StartOf;

export function now(): number {
  return moment().unix();
}
export function checkBetween(ts: number, start: number, end: number): boolean {
  return ts >= start && ts <= end;
}

export function checkNew(
  ts1: number,
  ts2: number,
  type: StartOf,
  delta = 14400000,
): boolean {
  return moment(ts1 - delta).isSame(moment(ts2 - delta), type);
}
