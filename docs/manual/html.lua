-- Match PDF figures to the PNG files produced by generate.sh.
function Image(image)
  image.src = image.src:gsub('%.pdf$', '.png')
  return image
end

-- Pandoc reads acro's label but does not expand its configured short form.
function Span(span)
  if span.attributes['acronym-label'] == 'sihft' then
    span.content = {pandoc.Str('SIHFT')}
    return span
  end
end
