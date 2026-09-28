# frozen_string_literal: true

# Replays the File_line resources a catalogue declares for one file, in
# catalogue order, the way stdlib's file_line provider applies them, and
# returns the resulting content.
#
# Start from '' to see what a fresh node gets. Start from a file an earlier
# release wrote to see what an upgrade does to it.
module FileLines
  def apply_file_lines(catalogue, path, content = '')
    lines = content.lines.map(&:chomp)

    file_lines(catalogue, path).each do |r|
      match = r[:match] && Regexp.new(r[:match])

      if r[:ensure].to_s == 'absent'
        lines.reject! { |l| match ? match.match?(l) : l == r[:line] }
        next
      end

      # A line that does not match its own match is appended on every run.
      raise "#{r} writes a line its match does not match" if match && !match.match?(r[:line])

      next if lines.include?(r[:line])

      if match && lines.any? { |l| match.match?(l) }
        lines.map! { |l| match.match?(l) ? r[:line] : l } unless r[:replace].to_s == 'false'
      else
        lines << r[:line]
      end
    end

    lines.empty? ? '' : "#{lines.join("\n")}\n"
  end

  # The File_lines that would change `content`. Empty for a file Puppet has
  # already converged; anything listed would report a change on every run.
  def file_line_changes(catalogue, path, content)
    lines = content.lines.map(&:chomp)

    changes = file_lines(catalogue, path).reject do |r|
      match = r[:match] && Regexp.new(r[:match])

      if r[:ensure].to_s == 'absent'
        lines.none? { |l| match ? match.match?(l) : l == r[:line] }
      else
        lines.include?(r[:line]) || (r[:replace].to_s == 'false' && lines.any? { |l| match.match?(l) })
      end
    end

    changes.map(&:to_s)
  end

  def file_lines(catalogue, path)
    catalogue.resources.select { |r| r.type == 'File_line' && r[:path] == path }
  end

  # The rules in a file an earlier release rendered, without its comments and
  # blank lines.
  def rules_in(content)
    content.lines.map(&:chomp).reject { |l| l.empty? || l.start_with?('#') }.map { |l| "#{l}\n" }.join
  end
end
