export function toCamelCase(str: string): string {
    return str.toLowerCase().replace(/(_[a-z])/g, (group) => group.toUpperCase().replace('_', ''));
}