local figure_prefix = ''

local function read_metadata(meta)
  figure_prefix = pandoc.utils.stringify(meta['figure-prefix'] or '')
end

-- Match PDF figures to PNGs, relative to either manual HTML route.
local function image_path(image)
  image.src = image.src:gsub('%.pdf$', '.png')
  if #image.caption == 0 then
    local descriptions = {
      ['figs/compas.png'] = 'COMPAS logo',
      ['figs/llc.png'] = 'LLVM static compiler reporting RISC-V target support'
    }
    if descriptions[image.src] then
      image.caption = {pandoc.Str(descriptions[image.src])}
    end
  end
  if image.src:match('^figs/') then
    image.src = figure_prefix .. image.src
  end
  return image
end

-- Pandoc reads acro's label but does not expand its configured short form.
local function expand_acronym(span)
  if span.attributes['acronym-label'] == 'sihft' then
    span.content = {pandoc.Str('SIHFT')}
  end
  return span
end

-- Read metadata before walking images; Pandoc normally visits inlines first.
return {{Meta = read_metadata}, {Image = image_path, Span = expand_acronym}}
