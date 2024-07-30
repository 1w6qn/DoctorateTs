export function now(): number {
    return parseInt((new Date().getTime()/1000).toString())
}