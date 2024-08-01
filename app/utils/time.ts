export function now(): number {
    return parseInt((new Date().getTime()/1000).toString())
}
export function checkBetween(ts: number, start: number, end: number): boolean {
    return ts >= start && ts <= end
}
export function checkNewDay(ts1: number,ts2: number,delta=14400000): boolean {
    return false//new Date(ts1*1000-delta).getDate()!=ts2
}
export function checkNewMonth(ts1: number,ts2: number,delta=14400000): boolean {
    return false//new Date(ts1*1000-delta).getMonth()!=ts2
}
export function checkNewYear(ts1: number,ts2: number,delta=14400000): boolean {
    return false//new Date(ts1*1000-delta).getFullYear()!=ts2
}
export function checkNewWeek(ts1: number,ts2: number,delta=14400000): boolean {
    return false//new Date(ts1*1000-delta).getDay()!=ts2
}