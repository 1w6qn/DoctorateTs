namespace Logger {
    export function formatDate(time: string | number | Date = new Date().getTime(), format: string = 'YY-MM-DD hh:mm:ss'): string {
        let date = new Date(time);
        let year = date.getFullYear(),
            month = date.getMonth() + 1,
            day = date.getDate(),
            hour = date.getHours(),
            min = date.getMinutes(),
            sec = date.getSeconds();
        let preArr = Array.apply(null, Array(10))
            .map(function (value: unknown, index: number, array: unknown[]) {
                return '0' + index;
            });
        return format.replace(/YY/g, year.toString())
            .replace(/MM/g, (preArr[month] || month) as string)
            .replace(/DD/g, (preArr[day] || day) as string)
            .replace(/hh/g, (preArr[hour] || hour) as string)
            .replace(/mm/g, (preArr[min] || min) as string)
            .replace(/ss/g, (preArr[sec] || sec) as string);
    }

    export function l(s: string): void {
        console.log(s);
        //if (SETTING['LogToAdb']) Java.perform(() => Java.use('android.util.Log').d(SETTING['LogTag'], s));
    }

    function getTime(): string {
        return '[1;30m[' + formatDate(new Date().getTime(), 'hh:mm:ss') + '] -[m '
    }

    function getTC(t: string | undefined = undefined): string {
        return t == undefined ? '' : `[1;35m${t} -[m `;
    }

    export function log(s: string, t: string | undefined = undefined): void {
        l(getTime() + getTC(t) + s);
    }

    export function logDebug(s: string, t: string | undefined = undefined): void {
        l(getTime() + getTC(t) + `[33;47m${s}[m`);
    }

    export function logNormal(s: string, t: string | undefined = undefined): void {
        l(getTime() + getTC(t) + `[1;34m${s}[m`);
    }

    export function logWell(s: string, t: string | undefined = undefined): void {
        l(getTime() + getTC(t) + `[1;32m${s}[m`);
    }

    export function logWarning(s: string, t: string | undefined = undefined): void {
        l(getTime() + getTC(t) + `[1;33m${s}[m`);
    }

    export function logError(s: string, t: string | undefined = undefined): void {
        l(getTime() + getTC(t) + `[1;31m${s}[m`);
    }
}
