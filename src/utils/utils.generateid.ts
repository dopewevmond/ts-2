/**
 * Returns a random alphanumeric string
 *
 * @param length - preferred string length
 * @returns Random alphanumeric string of length `length`
 */
const makeid = (length: number): string => {
  let result = ''
  const characters =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  const charactersLength = characters.length
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength))
  }
  return result
}

export default makeid
