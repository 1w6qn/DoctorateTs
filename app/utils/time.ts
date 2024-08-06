import moment from "moment"
export function now(): number {
    return moment().unix()
}
export function checkBetween(ts: number, start: number, end: number): boolean {
    return ts >= start && ts <= end
}
export function checkNewDay(ts1: number,ts2: number,delta=14400000): boolean {
    return moment(ts1).isSame(moment(ts2),'day')
}
export function checkNewMonth(ts1: number,ts2: number,delta=14400000): boolean {
    return moment(ts1).isSame(moment(ts2),'month')
}
export function checkNewYear(ts1: number,ts2: number,delta=14400000): boolean {
    return moment(ts1).isSame(moment(ts2),'year')
}
export function checkNewWeek(ts1: number,ts2: number,delta=14400000): boolean {
    return moment(ts1).isSame(moment(ts2),'week')
}